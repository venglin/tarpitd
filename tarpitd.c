/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Przemyslaw Frasunek <przemyslaw@frasunek.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * tarpitd - an SMTP tarpit daemon for FreeBSD
 *
 * Accepts SMTP connections that ipfw(8) has redirected here and holds them
 * open for as long as humanly possible, giving away one byte at a time and
 * reading their commands just as slowly.  Nothing is ever delivered, nothing
 * is ever permanently rejected: every terminal answer is a 4xx so the sender
 * requeues and comes back for more.
 *
 * Everything runs in a single process on one kqueue(2); a connection costs a
 * socket, ~1 KB of user memory and one timer.  Optionally forks workers that
 * share the listening sockets through SO_REUSEPORT_LB.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <libutil.h>
#endif
#ifdef WITH_CAPSICUM
#include <sys/capsicum.h>
#endif

#include "tarpitd.h"

#define NEVENTS		512
#define STATS_IDENT	0x7fffffff
#define IPHASHSZ	1024
#define LISTEN_BACKLOG	1024
#define TP_LINEAVG	48	/* typical reply line, for pacing estimates */

struct listener {
	int		kind;		/* K_LISTENER */
	int		fd;
	TAILQ_ENTRY(listener) link;
	char		name[TP_PEERMAX];
};

struct addrspec {
	TAILQ_ENTRY(addrspec) link;
	char		*host;
	char		*serv;
};

/* One entry per distinct source address, for the per-IP connection limit. */
struct ipent {
	LIST_ENTRY(ipent) link;
	uint32_t	n;
	uint8_t		key[16];
};

struct tp_cfg cfg = {
	.myname		= NULL,
	.verbose	= 0,
	.foreground	= 0,
	.maxconn	= 4096,
	.maxperip	= 16,
	.workers	= 1,
	.chunk		= 1,
	.drip_ms	= 20,
	.maxdrip_ms	= 30000,
	.budget_pct	= 80,
	.ramp_s		= 600,
	.greet_s	= 3,
	.banner_lines	= 24,
	.ehlo_pad	= 24,
	.maxsess_s	= 86400,
	.sockbuf	= 512,
	.logdata	= 1,
	.quit_hang	= 1,
	.tls_stall	= 1,
	.maxrcpt	= 200,
};

struct tp_stats stats;
time_t tp_now;
int64_t tp_now_ms;

static int64_t
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int kq = -1;
static volatile sig_atomic_t quitting;

/*
 * The batch kevent(2) is currently handing us.  One batch can hold several
 * events for the same connection - a timer and an EOF, say - so closing it
 * while processing the first would leave a dangling pointer in the rest.
 */
static struct kevent *cur_evs;
static int cur_nev;
static int cur_iev;

static int listening = -1;		/* are listeners armed? */
static char hostbuf[256];

static TAILQ_HEAD(, listener) listeners = TAILQ_HEAD_INITIALIZER(listeners);
static TAILQ_HEAD(, addrspec) addrspecs = TAILQ_HEAD_INITIALIZER(addrspecs);
static LIST_HEAD(, conn) conns = LIST_HEAD_INITIALIZER(conns);
static LIST_HEAD(iphash, ipent) iphash[IPHASHSZ];

/* ------------------------------------------------------------------ log */

void
tp_log(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (cfg.foreground) {
		char ts[32];
		struct tm tm;

		gmtime_r(&tp_now, &tm);
		strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
		fprintf(stderr, "%s ", ts);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
		fflush(stderr);
	} else
		vsyslog(pri, fmt, ap);
	va_end(ap);
}

/*
 * Fatal error.  Once daemon(3) has pointed stderr at /dev/null, err(3) would
 * take the reason for dying with it, so everything after that point has to
 * report through here instead.
 */
static void
tp_fatal(const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	tp_log(LOG_ERR, "fatal: %s", buf);
	exit(1);
}

/*
 * Everything a spammer sends us ends up in a log line sooner or later, so
 * strip anything that could forge log entries or upset a terminal.
 */
char *
tp_sanitize(char *dst, size_t dlen, const char *src, size_t slen)
{
	size_t i, o = 0;

	if (dlen == 0)
		return (dst);
	for (i = 0; i < slen && o + 1 < dlen; i++) {
		unsigned char ch = (unsigned char)src[i];

		if (ch == '\0')
			break;
		dst[o++] = (ch < 0x20 || ch >= 0x7f) ? '?' : (char)ch;
	}
	dst[o] = '\0';
	return (dst);
}

/* ------------------------------------------------------- per-IP limiter */

static uint32_t
iphash_idx(const uint8_t *key)
{
	uint32_t h = 2166136261u;
	int i;

	for (i = 0; i < 16; i++) {
		h ^= key[i];
		h *= 16777619u;
	}
	return (h & (IPHASHSZ - 1));
}

static void
ipkey(const struct sockaddr *sa, uint8_t key[16])
{
	static const uint8_t v4pfx[12] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
	};

	memset(key, 0, 16);
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)(const void *)sa;

		memcpy(key, v4pfx, 12);
		memcpy(key + 12, &s4->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)(const void *)sa;

		memcpy(key, &s6->sin6_addr, 16);
	}
}

/* Returns NULL when this address is already at its connection limit. */
static struct ipent *
ip_hold(const struct sockaddr *sa)
{
	struct ipent *e;
	uint8_t key[16];
	uint32_t h;

	if (cfg.maxperip <= 0)
		return (NULL);
	ipkey(sa, key);
	h = iphash_idx(key);
	LIST_FOREACH(e, &iphash[h], link) {
		if (memcmp(e->key, key, 16) == 0) {
			if (e->n >= (uint32_t)cfg.maxperip)
				return (NULL);
			e->n++;
			return (e);
		}
	}
	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);
	memcpy(e->key, key, 16);
	e->n = 1;
	LIST_INSERT_HEAD(&iphash[h], e, link);
	return (e);
}

static void
ip_release(struct ipent *e)
{

	if (e == NULL)
		return;
	if (--e->n == 0) {
		LIST_REMOVE(e, link);
		free(e);
	}
}

/* ---------------------------------------------------------- kqueue glue */

static int
kev(uintptr_t ident, short filter, u_short flags, u_int fflags, int64_t data,
    void *udata)
{
	struct kevent ke;

	EV_SET(&ke, ident, filter, flags, fflags, data, udata);
	return (kevent(kq, &ke, 1, NULL, 0, NULL));
}

static void
arm_timer(struct conn *c, int ms)
{
	u_int fflags = 0;

#ifdef NOTE_MSECONDS
	fflags = NOTE_MSECONDS;
#endif
	if (ms < 1)
		ms = 1;
	if (kev(c->fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, fflags, ms, c) == -1)
		tp_conn_close(c, "timer failed");
}

/* Timeouts RFC 5321 4.5.3.2 tells a sender to allow, per protocol stage. */
const int tp_phase_secs[PH_NPHASES] = {
	[PH_GREET]	= 300,
	[PH_CMD]	= 300,
	[PH_DATAINIT]	= 120,
	[PH_DATABLOCK]	= 180,
	[PH_DATADOT]	= 600
};

/*
 * Start a protocol stage: the reply we are about to produce has to be
 * complete by this deadline or the sender gives up on us.
 */
void
tp_phase(struct conn *c, int phase)
{

	if (phase < 0 || phase >= PH_NPHASES || cfg.budget_pct <= 0) {
		c->deadline = 0;
		return;
	}
	c->deadline = tp_now_ms +
	    (int64_t)tp_phase_secs[phase] * 10 * cfg.budget_pct;
}

/*
 * Bytes still to move before the current stage is finished.  Writing knows
 * exactly; reading has to guess, because the length of a command is up to
 * the sender.  The guess only has to be in the right region: the delay is
 * recomputed from the remaining time on every single byte, so an estimate
 * that was too low simply makes the tail of the reply hurry up.
 */
static long
work_left(const struct conn *c)
{
	long n;

	if (c->outpos < c->outlen || c->gen != G_NONE) {
		n = (long)(c->outlen - c->outpos) + (long)tp_gen_estimate(c);
		return (n > 0 ? n : 1);
	}
	return (96);			/* a command line, give or take */
}

/* ms per byte while swallowing a body, see the comment in delay_ms(). */
static long
body_rate(void)
{
	long buf = cfg.sockbuf > 0 ? cfg.sockbuf : 512;

	return ((long)tp_phase_secs[PH_DATABLOCK] * 10 * cfg.budget_pct / buf);
}

/*
 * Delay before the next byte moves in either direction.
 *
 * With a deadline set we simply divide the time left by the work left, so a
 * long reply is delivered briskly and a short one is stretched, and either
 * way it lands just inside the sender's patience.  That is the whole trick:
 * what buys time is the number of round trips survived, not the rate of any
 * one of them.
 */
static int
delay_ms(const struct conn *c)
{
	long base;
	long j;

	if (cfg.budget_pct > 0 &&
	    (c->state == S_DATA || c->state == S_BDAT)) {
		/*
		 * A body has no end we can aim at, so pace against the receive
		 * buffer instead.  The sender blocks once it is full and has
		 * to be released before its per-block timer runs out, which
		 * means draining one bufferful per block timeout.
		 */
		base = body_rate();
	} else if (cfg.budget_pct > 0 && c->gen != G_NONE &&
	    tp_gen_estimate(c) == 0) {
		/*
		 * An endless generator - a greeting with no last line, the TLS
		 * stall, a hanging QUIT - has no completion to be late for, so
		 * a deadline would simply expire and let the delay collapse to
		 * the floor, firehosing the peer we meant to hold.  Pace it at
		 * one line per timeout window instead: enough to keep the
		 * sender's inactivity timer fed, forever.
		 */
		base = (long)tp_phase_secs[PH_CMD] * 10 * cfg.budget_pct /
		    TP_LINEAVG;
	} else if (c->deadline > 0) {
		int64_t left = c->deadline - tp_now_ms;

		if (left < 0)
			left = 0;	/* late: the floor takes over */
		base = (long)(left / work_left(c));
	} else {
		long age = (long)(tp_now - c->start);

		base = cfg.drip_ms > 0 ? cfg.drip_ms : 1;
		if (cfg.ramp_s > 0) {
			long steps = age / cfg.ramp_s;

			while (steps-- > 0 && base < cfg.maxdrip_ms)
				base *= 2;
		}
	}

	if (c->flags & F_BADBOT)
		base *= 2;
	if (base > cfg.maxdrip_ms)
		base = cfg.maxdrip_ms;
	if (base < cfg.drip_ms)
		base = cfg.drip_ms;
	if (base < 1)
		base = 1;

	j = base / 4;
	if (j > 0)
		base += (long)arc4random_uniform((uint32_t)(2 * j)) - j;
	return ((int)(base < 1 ? 1 : base));
}

/* ----------------------------------------------------- connection state */

static void
listeners_arm(int on)
{
	static time_t lastflap;
	struct listener *l;

	if (listening == on)
		return;
	TAILQ_FOREACH(l, &listeners, link)
		kev(l->fd, EVFILT_READ, on ? EV_ENABLE : EV_DISABLE, 0, 0, l);
	listening = on;

	/*
	 * At saturation this flips on every close, so report it at most once
	 * a minute rather than filling the log with it.
	 */
	if (tp_now - lastflap >= 60) {
		lastflap = tp_now;
		tp_log(LOG_NOTICE, "%s accepting connections (%u active)",
		    on ? "resumed" : "paused", stats.cur);
	}
}

void
tp_conn_close(struct conn *c, const char *why)
{
	time_t held = tp_now - c->start;
	u_int fflags = 0;
	int i;

#ifdef NOTE_MSECONDS
	fflags = NOTE_MSECONDS;
#endif
	/*
	 * Disarm any further events for this connection that are already
	 * sitting in the batch being processed.  EVFILT_* are all negative,
	 * so zero is a safe "ignore me" marker.
	 */
	for (i = cur_iev + 1; i < cur_nev; i++) {
		if (cur_evs[i].udata == c)
			cur_evs[i].filter = 0;
	}

	/*
	 * Timers are not tied to the descriptor, so an armed one has to be
	 * cancelled explicitly or it will fire on whichever connection
	 * inherits this fd next.
	 */
	kev(c->fd, EVFILT_TIMER, EV_DELETE, fflags, 0, NULL);
	close(c->fd);

	if (held < 0)
		held = 0;
	stats.wasted += (uint64_t)held;
	stats.rx += c->rx;
	stats.tx += c->tx;
	if (stats.cur > 0)
		stats.cur--;

	if (cfg.verbose >= 1)
		tp_log(LOG_INFO,
		    "close %s held=%llds cmds=%u rcpt=%u body=%llu rx=%llu tx=%llu%s (%s)",
		    c->peer, (long long)held, c->ncmd, c->nrcpt,
		    (unsigned long long)c->dbytes, (unsigned long long)c->rx,
		    (unsigned long long)c->tx,
		    (c->flags & F_BADBOT) ? " early-talker" : "", why);

	LIST_REMOVE(c, link);
	ip_release(c->ipe);
	free(c);

	if (!listening && stats.cur < (uint32_t)cfg.maxconn)
		listeners_arm(1);
}

/* Returns 0 if the connection was closed. */
static int
conn_write(struct conn *c)
{
	ssize_t n;
	size_t want = c->outlen - c->outpos;

	if (want > (size_t)cfg.chunk)
		want = (size_t)cfg.chunk;
	n = write(c->fd, c->out + c->outpos, want);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return (1);	/* their window is shut; try later */
		tp_conn_close(c, strerror(errno));
		return (0);
	}
	c->outpos += (uint16_t)n;
	c->tx += (uint64_t)n;

	if (c->outpos >= c->outlen && c->gen == G_NONE) {
		c->state = c->next;
		if (c->state == S_CLOSE) {
			tp_conn_close(c, "goodbye");
			return (0);
		}
		/*
		 * Their reply timer starts the moment they finish sending,
		 * which is while we are still reading it a byte at a time.
		 * Reading and answering therefore share one budget, opened
		 * here rather than when the answer is finally queued.
		 */
		if (c->state == S_CMD || c->state == S_AUTH)
			tp_phase(c, PH_CMD);
	}
	return (1);
}

static int
conn_read(struct conn *c)
{
	unsigned char b;
	ssize_t n;

	/*
	 * Always exactly one byte per tick.  It is the whole point - their
	 * send buffer never drains - and it also means a reply queued in the
	 * middle of a batch can never make us discard bytes we had already
	 * pulled out of the socket.
	 */
	n = read(c->fd, &b, 1);
	if (n == 0) {
		tp_conn_close(c, "peer closed");
		return (0);
	}
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return (1);
		tp_conn_close(c, strerror(errno));
		return (0);
	}
	c->rx += (uint64_t)n;
	tp_input(c, &b, 1);
	return (1);
}

static void
conn_tick(struct conn *c)
{

	if (cfg.maxsess_s > 0 && tp_now - c->start >= cfg.maxsess_s) {
		tp_conn_close(c, "session limit");
		return;
	}
	if (c->eof) {
		tp_conn_close(c, "peer closed");
		return;
	}

	/* Output always wins: SMTP is half duplex and so are we. */
	if (c->outpos >= c->outlen && c->gen != G_NONE)
		tp_refill(c);

	if (c->outpos < c->outlen) {
		if (!conn_write(c))
			return;
	} else {
		if (!conn_read(c))
			return;
	}
	arm_timer(c, delay_ms(c));
}

static void
conn_readable(struct conn *c, int eof)
{

	/*
	 * We never read here - reading is what the timer is for.  This only
	 * tells us that something arrived, which during the greeting means
	 * the peer spoke out of turn.  No conforming client does that, so it
	 * earns extra punishment.
	 */
	if (eof)
		c->eof = 1;
	else if (c->state == S_BANNER && !(c->flags & F_BADBOT))
		tp_early_talker(c);
}

static void
sock_tune(int fd)
{
	int one = 1;
	int v;

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	/*
	 * Tiny socket buffers shrink the window we advertise, so the spammer
	 * can only ever have a few hundred bytes in flight and blocks in
	 * send() almost immediately.  It also keeps our own kernel memory
	 * per connection down to near nothing.
	 */
	if (cfg.sockbuf > 0) {
		v = cfg.sockbuf;
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));
		v = cfg.sockbuf;
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
	}

	/* Reap peers that vanish without a FIN, or we leak descriptors. */
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
	v = 300;
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof(v));
	v = 60;
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof(v));
	v = 4;
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &v, sizeof(v));
#endif
#ifdef SO_NOSIGPIPE
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
}

static void
addr_str(const struct sockaddr *sa, socklen_t salen, char *dst, size_t dlen)
{
	char h[NI_MAXHOST], s[NI_MAXSERV];

	if (getnameinfo(sa, salen, h, sizeof(h), s, sizeof(s),
	    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		snprintf(dst, dlen, "unknown");
		return;
	}
	if (sa->sa_family == AF_INET6)
		snprintf(dst, dlen, "[%s]:%s", h, s);
	else
		snprintf(dst, dlen, "%s:%s", h, s);
}

static void
do_accept(struct listener *l)
{
	struct sockaddr_storage ss, ds;
	socklen_t slen, dlen;
	struct conn *c;
	struct ipent *ipe;
	char pbuf[TP_PEERMAX], dbuf[TP_PEERMAX];
	int fd, i;

	/* Drain the queue in bounded batches so one listener cannot starve
	 * the others or the timers. */
	for (i = 0; i < 64; i++) {
		if (stats.cur >= (uint32_t)cfg.maxconn) {
			/*
			 * At capacity we simply stop accepting.  The excess
			 * piles up in the kernel's listen queue, where the
			 * senders sit connected and silent - free tarpitting
			 * that costs us no descriptors at all.
			 */
			listeners_arm(0);
			return;
		}

		slen = sizeof(ss);
#ifdef SOCK_NONBLOCK
		fd = accept4(l->fd, (struct sockaddr *)&ss, &slen,
		    SOCK_NONBLOCK);
#else
		fd = accept(l->fd, (struct sockaddr *)&ss, &slen);
		if (fd >= 0)
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (errno == EMFILE || errno == ENFILE) {
				tp_log(LOG_WARNING,
				    "accept: %s, pausing", strerror(errno));
				listeners_arm(0);
				return;
			}
			tp_log(LOG_WARNING, "accept: %s", strerror(errno));
			return;
		}

		if ((ipe = ip_hold((struct sockaddr *)&ss)) == NULL &&
		    cfg.maxperip > 0) {
			stats.refused++;
			close(fd);
			continue;
		}

		if ((c = calloc(1, sizeof(*c))) == NULL) {
			ip_release(ipe);
			close(fd);
			tp_log(LOG_WARNING, "out of memory, dropping");
			continue;
		}

		sock_tune(fd);

		c->kind = K_CONN;
		c->fd = fd;
		c->ipe = ipe;
		c->start = tp_now;
		c->prod = (uint8_t)arc4random_uniform(8);

		addr_str((struct sockaddr *)&ss, slen, pbuf, sizeof(pbuf));
		/*
		 * With ipfw fwd the socket keeps the original destination,
		 * so this records which address of ours they were aiming at.
		 */
		dlen = sizeof(ds);
		if (getsockname(fd, (struct sockaddr *)&ds, &dlen) == 0)
			addr_str((struct sockaddr *)&ds, dlen, dbuf,
			    sizeof(dbuf));
		else
			snprintf(dbuf, sizeof(dbuf), "?");
		snprintf(c->peer, sizeof(c->peer), "%s>%s", pbuf, dbuf);

		LIST_INSERT_HEAD(&conns, c, link);
		stats.conns++;
		stats.cur++;
		if (stats.cur > stats.peak)
			stats.peak = stats.cur;

		if (cfg.verbose >= 1)
			tp_log(LOG_INFO, "open %s (%u active)", c->peer,
			    stats.cur);

		/*
		 * EV_CLEAR because we deliberately leave their data sitting
		 * in the receive buffer; level triggering would spin.
		 */
		if (kev(fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, c) == -1) {
			tp_conn_close(c, "kevent failed");
			continue;
		}
		tp_open(c);
		arm_timer(c, cfg.greet_s * 1000 +
		    (int)arc4random_uniform(2000));
	}
}

/* -------------------------------------------------------------- sockets */

static int
listener_add(const char *host, const char *serv)
{
	struct addrinfo hints, *res, *ai;
	struct listener *l;
	int e, n = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

	if ((e = getaddrinfo(host, serv, &hints, &res)) != 0) {
		tp_log(LOG_ERR, "%s:%s: %s", host ? host : "*", serv,
		    gai_strerror(e));
		return (0);
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		int fd, one = 1;

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT_LB
		if (cfg.workers > 1)
			setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, &one,
			    sizeof(one));
#endif
#ifdef IPV6_V6ONLY
		if (ai->ai_family == AF_INET6)
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one,
			    sizeof(one));
#endif
		/*
		 * Set the buffers before listen() so the small window is
		 * already in place for the SYN/ACK and window scaling is
		 * negotiated accordingly.
		 */
		if (cfg.sockbuf > 0) {
			int v = cfg.sockbuf;

			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));
			v = cfg.sockbuf;
			setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
		}
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

		if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			char nb[TP_PEERMAX];

			addr_str(ai->ai_addr, ai->ai_addrlen, nb, sizeof(nb));
			tp_log(LOG_ERR, "bind %s: %s", nb, strerror(errno));
			close(fd);
			continue;
		}
		if (listen(fd, LISTEN_BACKLOG) < 0) {
			tp_log(LOG_ERR, "listen: %s", strerror(errno));
			close(fd);
			continue;
		}
		if ((l = calloc(1, sizeof(*l))) == NULL) {
			close(fd);
			continue;
		}
		l->kind = K_LISTENER;
		l->fd = fd;
		addr_str(ai->ai_addr, ai->ai_addrlen, l->name, sizeof(l->name));
		TAILQ_INSERT_TAIL(&listeners, l, link);
		n++;
	}
	freeaddrinfo(res);
	return (n);
}

/*
 * Accepts "addr:port", "[v6addr]:port", "addr" and "port".
 */
static void
addrspec_add(const char *arg, const char *defport)
{
	struct addrspec *as;
	char *s, *p;

	if ((as = calloc(1, sizeof(*as))) == NULL)
		err(1, "calloc");
	if ((s = strdup(arg)) == NULL)
		err(1, "strdup");

	if (*s == '[') {
		if ((p = strchr(s, ']')) == NULL)
			errx(1, "%s: unterminated address", arg);
		*p++ = '\0';
		as->host = strdup(s + 1);
		as->serv = strdup(*p == ':' ? p + 1 : defport);
	} else if ((p = strrchr(s, ':')) != NULL && strchr(s, ':') == p) {
		*p = '\0';
		as->host = strdup(s);
		as->serv = strdup(p + 1);
	} else if (strspn(s, "0123456789") == strlen(s) && *s != '\0') {
		as->host = NULL;
		as->serv = strdup(s);
	} else {
		as->host = strdup(s);
		as->serv = strdup(defport);
	}
	free(s);
	TAILQ_INSERT_TAIL(&addrspecs, as, link);
}

/* ---------------------------------------------------------------- stats */

static void
dump_stats(void)
{

	tp_log(LOG_NOTICE,
	    "stats: active=%u peak=%u total=%llu refused=%llu wasted=%lluh%llum "
	    "bodies=%llu auth=%llu tls=%llu cmds=%llu rx=%llu tx=%llu",
	    stats.cur, stats.peak, (unsigned long long)stats.conns,
	    (unsigned long long)stats.refused,
	    (unsigned long long)(stats.wasted / 3600),
	    (unsigned long long)((stats.wasted % 3600) / 60),
	    (unsigned long long)stats.msgs, (unsigned long long)stats.auths,
	    (unsigned long long)stats.tlss, (unsigned long long)stats.cmds,
	    (unsigned long long)stats.rx, (unsigned long long)stats.tx);
}

/* ------------------------------------------------------------ main loop */

static void
run(void)
{
	struct kevent evs[NEVENTS];
	struct listener *l;
	int i, n;
	u_int tfflags = 0;

#ifdef NOTE_MSECONDS
	tfflags = NOTE_MSECONDS;
#endif
	if ((kq = kqueue()) < 0)
		tp_fatal("kqueue: %s", strerror(errno));

	TAILQ_FOREACH(l, &listeners, link) {
		if (kev(l->fd, EVFILT_READ, EV_ADD, 0, 0, l) == -1)
			tp_fatal("kevent listener: %s", strerror(errno));
	}
	listening = 1;

	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	kev(SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	kev(SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	kev(SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
#ifdef SIGINFO
	signal(SIGINFO, SIG_IGN);
	kev(SIGINFO, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
#endif
	/* Hourly summary to syslog. */
	kev(STATS_IDENT, EVFILT_TIMER, EV_ADD, tfflags, 3600 * 1000, NULL);

	tp_log(LOG_NOTICE, "tarpitd ready (pid %ld, max %d connections)",
	    (long)getpid(), cfg.maxconn);

	while (!quitting) {
		n = kevent(kq, NULL, 0, evs, NEVENTS, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			tp_log(LOG_ERR, "kevent: %s", strerror(errno));
			break;
		}
		tp_now = time(NULL);
		tp_now_ms = now_ms();

		cur_evs = evs;
		cur_nev = n;
		for (i = 0; i < n; i++) {
			struct kevent *ev = &evs[i];
			int *kind = ev->udata;

			cur_iev = i;

			switch (ev->filter) {
			case EVFILT_SIGNAL:
				switch ((int)ev->ident) {
				case SIGTERM:
				case SIGINT:
					quitting = 1;
					break;
#ifdef SIGINFO
				case SIGINFO:
#endif
				case SIGHUP:
					dump_stats();
					break;
				}
				break;

			case EVFILT_TIMER:
				if (ev->ident == STATS_IDENT) {
					dump_stats();
					break;
				}
				conn_tick((struct conn *)ev->udata);
				break;

			case EVFILT_READ:
				if (kind == NULL)
					break;
				if (*kind == K_LISTENER)
					do_accept((struct listener *)ev->udata);
				else
					conn_readable((struct conn *)ev->udata,
					    (ev->flags & EV_EOF) != 0);
				break;

			default:		/* disarmed above */
				break;
			}
		}
		cur_evs = NULL;
		cur_nev = 0;
	}

	tp_log(LOG_NOTICE, "shutting down, %u connections released", stats.cur);
	dump_stats();
}

/* ----------------------------------------------------------- privileges */

static void
drop_privs(const char *user, const char *jail)
{
	struct passwd *pw = NULL;
	uid_t uid = getuid();

	if (user != NULL && *user != '\0') {
		if ((pw = getpwnam(user)) == NULL)
			tp_fatal("unknown user %s", user);
	}
	endpwent();

	/*
	 * Being started as an unprivileged user is legitimate as long as it
	 * is the user we were going to become anyway; the caller has already
	 * done the job.  Anything else cannot work, and saying so plainly
	 * beats failing in setgroups() with EPERM.
	 */
	if (uid != 0) {
		if (pw != NULL && pw->pw_uid != uid)
			tp_fatal("started as uid %ld, cannot become %s "
			    "(uid %ld): run as root, or drop the -u flag",
			    (long)uid, user, (long)pw->pw_uid);
		if (jail != NULL)
			tp_fatal("chroot %s needs root", jail);
		return;
	}

	if (jail != NULL) {
		if (chroot(jail) < 0)
			tp_fatal("chroot %s: %s", jail, strerror(errno));
		if (chdir("/") < 0)
			tp_fatal("chdir /: %s", strerror(errno));
	}
	if (pw != NULL) {
		if (setgroups(1, &pw->pw_gid) < 0)
			tp_fatal("setgroups: %s", strerror(errno));
		if (setgid(pw->pw_gid) < 0)
			tp_fatal("setgid: %s", strerror(errno));
		if (setuid(pw->pw_uid) < 0)
			tp_fatal("setuid: %s", strerror(errno));
		if (pw->pw_uid != 0 && setuid(0) == 0)
			tp_fatal("still able to regain root");
	}
}

static void
raise_nofile(int want)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		return;
	if ((rlim_t)want <= rl.rlim_cur)
		return;
	rl.rlim_cur = (rlim_t)want;
	if (rl.rlim_max < rl.rlim_cur)
		rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
	    (rlim_t)want > rl.rlim_cur) {
		int avail = (int)rl.rlim_cur - 32;

		if (avail < 16)
			avail = 16;
		if (cfg.maxconn > avail) {
			tp_log(LOG_WARNING,
			    "descriptor limit caps connections at %d", avail);
			cfg.maxconn = avail;
		}
	}
}

/* --------------------------------------------------------- process tree */

#define MAXWORKERS	64

static pid_t workers[MAXWORKERS];
static int nworkers;

static void
worker(const char *user, const char *jail)
{
	struct addrspec *as;
	struct listener *l;
	int nl = 0;

	TAILQ_FOREACH(as, &addrspecs, link)
		nl += listener_add(as->host, as->serv);
	if (nl == 0)
		tp_fatal("no listening sockets");
	TAILQ_FOREACH(l, &listeners, link)
		tp_log(LOG_NOTICE, "listening on %s", l->name);

	drop_privs(user, jail);

#ifdef WITH_CAPSICUM
	/*
	 * Everything still needed (accept, read, write, close, kevent) is
	 * allowed in capability mode; we never open another file.
	 */
	if (cap_enter() < 0 && errno != ENOSYS)
		tp_fatal("cap_enter: %s", strerror(errno));
#endif

	run();
}

static void
sup_signal(int sig)
{
	int i;

	for (i = 0; i < nworkers; i++) {
		if (workers[i] > 0)
			kill(workers[i], sig);
	}
	quitting = 1;
}

/*
 * With more than one worker each child binds its own listening socket with
 * SO_REUSEPORT_LB, so the kernel spreads inbound connections over them by
 * 4-tuple hash.  The parent only keeps them alive.
 */
static void
supervise(const char *user, const char *jail)
{
	int i;

	nworkers = cfg.workers > MAXWORKERS ? MAXWORKERS : cfg.workers;
	for (i = 0; i < nworkers; i++) {
		pid_t p = fork();

		if (p < 0)
			tp_fatal("fork: %s", strerror(errno));
		if (p == 0) {
			worker(user, jail);
			_exit(0);
		}
		workers[i] = p;
	}
	signal(SIGTERM, sup_signal);
	signal(SIGINT, sup_signal);

	while (!quitting) {
		pid_t p = wait(NULL);

		if (p < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (i = 0; i < nworkers; i++) {
			if (workers[i] != p)
				continue;
			workers[i] = -1;
			if (quitting)
				break;
			tp_log(LOG_ERR, "worker %ld died, restarting",
			    (long)p);
			sleep(1);
			if ((p = fork()) == 0) {
				worker(user, jail);
				_exit(0);
			}
			workers[i] = p;
			break;
		}
	}
	for (;;) {
		if (wait(NULL) < 0 && errno != EINTR)
			break;
	}
}

static void
usage(void)
{

	fprintf(stderr,
"usage: tarpitd [-dv] [-l addr[:port]] [-p port] [-u user] [-r chroot]\n"
"               [-P pidfile] [-n workers] [-c maxconn] [-i per-ip]\n"
"               [-S min-ms] [-M max-ms] [-X budget-pct] [-R ramp-s]\n"
"               [-g greet-s]\n"
"               [-b banner-lines] [-e ehlo-pad] [-T max-session-s]\n"
"               [-B chunk] [-w sockbuf] [-H hostname] [-Q] [-t] [-L]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *user = "nobody";
	const char *jail = NULL;
	const char *pidfile = NULL;
	const char *defport = "8025";
	int ch, i;
#ifdef __FreeBSD__
	struct pidfh *pfh = NULL;
#endif

	tp_now = time(NULL);
	for (i = 0; i < IPHASHSZ; i++)
		LIST_INIT(&iphash[i]);

	while ((ch = getopt(argc, argv,
	    "B:H:LM:P:QR:S:T:X:b:c:de:g:i:l:n:p:r:tu:vw:")) != -1) {
		switch (ch) {
		case 'B':
			cfg.chunk = atoi(optarg);
			break;
		case 'H':
			cfg.myname = optarg;
			break;
		case 'L':
			cfg.logdata = 0;
			break;
		case 'M':
			cfg.maxdrip_ms = atoi(optarg);
			break;
		case 'P':
			pidfile = optarg;
			break;
		case 'Q':
			cfg.quit_hang = 0;
			break;
		case 'R':
			cfg.ramp_s = atoi(optarg);
			break;
		case 'S':
			cfg.drip_ms = atoi(optarg);
			break;
		case 'T':
			cfg.maxsess_s = atoi(optarg);
			break;
		case 'X':
			cfg.budget_pct = atoi(optarg);
			break;
		case 'b':
			cfg.banner_lines = atoi(optarg);
			break;
		case 'c':
			cfg.maxconn = atoi(optarg);
			break;
		case 'd':
			cfg.foreground = 1;
			break;
		case 'e':
			cfg.ehlo_pad = atoi(optarg);
			break;
		case 'g':
			cfg.greet_s = atoi(optarg);
			break;
		case 'i':
			cfg.maxperip = atoi(optarg);
			break;
		case 'l':
			addrspec_add(optarg, defport);
			break;
		case 'n':
			cfg.workers = atoi(optarg);
			break;
		case 'p':
			defport = optarg;
			break;
		case 'r':
			jail = optarg;
			break;
		case 't':
			cfg.tls_stall = 0;
			break;
		case 'u':
			user = optarg;
			break;
		case 'v':
			cfg.verbose++;
			break;
		case 'w':
			cfg.sockbuf = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	if (cfg.chunk < 1)
		cfg.chunk = 1;
	if (cfg.chunk > 64)
		cfg.chunk = 64;
	if (cfg.drip_ms < 1)
		cfg.drip_ms = 1;
	if (cfg.maxdrip_ms < cfg.drip_ms)
		cfg.maxdrip_ms = cfg.drip_ms;
	if (cfg.budget_pct < 0)
		cfg.budget_pct = 0;
	if (cfg.budget_pct > 95)
		cfg.budget_pct = 95;	/* leave the sender some margin */
	if (cfg.maxconn < 1)
		cfg.maxconn = 1;
	if (cfg.workers < 1)
		cfg.workers = 1;
	if (cfg.banner_lines < 0)
		cfg.banner_lines = 0;
	if (cfg.ehlo_pad < 0)
		cfg.ehlo_pad = 0;
	if (cfg.maxrcpt < 1)
		cfg.maxrcpt = 1;

	if (cfg.myname == NULL) {
		if (gethostname(hostbuf, sizeof(hostbuf)) != 0 ||
		    hostbuf[0] == '\0')
			strlcpy(hostbuf, "mail.example.net", sizeof(hostbuf));
		hostbuf[sizeof(hostbuf) - 1] = '\0';
		cfg.myname = hostbuf;
	}

	if (TAILQ_EMPTY(&addrspecs))
		addrspec_add("127.0.0.1", defport);

	openlog("tarpitd", LOG_PID | LOG_NDELAY, LOG_MAIL);
	signal(SIGPIPE, SIG_IGN);
	raise_nofile(cfg.maxconn + 32);

#ifdef __FreeBSD__
	if (pidfile != NULL) {
		pid_t other;

		pfh = pidfile_open(pidfile, 0600, &other);
		if (pfh == NULL) {
			if (errno == EEXIST)
				errx(1, "already running as pid %ld",
				    (long)other);
			warn("pidfile_open %s", pidfile);
		}
	}
#else
	(void)pidfile;
#endif

	if (!cfg.foreground) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
	}
#ifdef __FreeBSD__
	if (pfh != NULL)
		pidfile_write(pfh);
#endif

	if (cfg.workers > 1)
		supervise(user, jail);
	else
		worker(user, jail);

#ifdef __FreeBSD__
	if (pfh != NULL)
		pidfile_remove(pfh);
#endif
	closelog();
	return (0);
}
