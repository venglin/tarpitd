/*-
 * tarpitd - SMTP dialogue state machine.
 *
 * The whole point is to look like a slow but perfectly ordinary MTA.  Every
 * answer is syntactically valid so a sender has no reason to give up, but it
 * arrives one byte at a time, and every terminal answer is a 4xx so the
 * message stays in the sender's queue and comes back to us again later.
 */

#include <sys/types.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "tarpitd.h"

#define NITEMS(a)	(sizeof(a) / sizeof((a)[0]))

/* Rotated per connection so a scanner cannot fingerprint one banner. */
static const char *products[] = {
	"Postfix",
	"Sendmail 8.17.1/8.17.1",
	"Exim 4.96",
	"Microsoft ESMTP MAIL Service, Version: 10.0.17763.1",
	"OpenSMTPD",
	"Zimbra 8.8.15_GA_4372",
	"qmail 1.03",
	"MailEnable Service, Version: 10.26"
};

static const char *stall_msgs[] = {
	"Please wait, we are verifying your connection",
	"Anti-spam measures in effect, this may take a moment",
	"Checking sender reputation against local policy",
	"DNSBL lookups in progress, do not disconnect",
	"Greylisting engine is warming up",
	"Reverse DNS verification pending",
	"SPF and DMARC evaluation in progress",
	"Content filter is still loading rule sets",
	"Your connection has been queued behind other clients",
	"Rate limiting active for your network range",
	"Please be patient, this server is under heavy load",
	"Message hygiene checks are running",
	"Verifying that you are a conforming SMTP client",
	"Backscatter protection is analysing your session",
	"Policy daemon has not answered yet, retrying",
	"Thank you for your patience"
};

static const char *ehlo_exts[] = {
	"PIPELINING",
	"SIZE 78643200",
	"ETRN",
	"ENHANCEDSTATUSCODES",
	"8BITMIME",
	"DSN",
	"SMTPUTF8",
	"CHUNKING",
	"BINARYMIME",
	"VRFY",
	"EXPN",
	"HELP",
	"DELIVERBY 86400",
	"NO-SOLICITING",
	"MT-PRIORITY MIXER",
	"FUTURERELEASE 86400 9999-12-31T23:59:59Z",
	"REQUIRETLS",
	"RRVS",
	"CONNEG",
	"CONPERM",
	"ATRN",
	"BURL imap",
	"XVERP",
	"XFORWARD NAME ADDR PROTO HELO SOURCE PORT IDENT",
	"XCLIENT NAME ADDR PROTO HELO LOGIN DESTADDR DESTPORT",
	"XSHADOW",
	"AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 NTLM",
	"AUTH=PLAIN LOGIN CRAM-MD5 DIGEST-MD5 NTLM"
};

static const char *tempfails[] = {
	"451 4.3.0 Error: queue file write error, please retry later",
	"450 4.7.1 Greylisted, please retry in 300 seconds",
	"451 4.3.2 Please try again later, system incorrectly configured",
	"452 4.3.1 Insufficient system storage, retry later",
	"451 4.7.1 Content scanner temporarily unavailable, retry later",
	"450 4.2.0 Mailbox busy, please retry"
};

static const char *helplines[] = {
	"214-This server implements the following commands:",
	"214-HELO EHLO MAIL RCPT DATA BDAT RSET NOOP QUIT",
	"214-VRFY EXPN HELP STARTTLS AUTH ETRN TURN",
	"214-For local information contact the postmaster.",
	"214-Please note that all sessions are logged and rate limited.",
	"214-Delivery may be delayed while policy checks complete.",
	"214-See RFC 5321 for the definition of these commands."
};

static const char *fake_users[] = {
	"john.smith", "mary.jones", "sales", "info", "support", "billing",
	"admin", "webmaster", "hr", "accounts", "noreply", "helpdesk",
	"p.kowalski", "a.nowak", "office", "contact", "orders", "invoice"
};

/* ------------------------------------------------------------- plumbing */

static void
out_vline(struct conn *c, const char *fmt, va_list ap)
{
	int n;

	n = vsnprintf(c->out, sizeof(c->out) - 2, fmt, ap);
	if (n < 0)
		n = 0;
	if ((size_t)n > sizeof(c->out) - 3)
		n = (int)sizeof(c->out) - 3;
	c->out[n++] = '\r';
	c->out[n++] = '\n';
	c->outlen = (uint16_t)n;
	c->outpos = 0;
}

/* One line from a multiline generator; leaves c->gen alone. */
static void
gen_line(struct conn *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	out_vline(c, fmt, ap);
	va_end(ap);
}

/* A complete single-line reply; the session moves to nxt once it drains. */
static void
respond(struct conn *c, int nxt, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	out_vline(c, fmt, ap);
	va_end(ap);
	c->gen = G_NONE;
	c->state = S_RESP;
	c->next = (uint8_t)nxt;
}

static const char *
product(const struct conn *c)
{

	return (products[c->prod % NITEMS(products)]);
}

static const char *
pick(const char **tab, size_t n)
{

	return (tab[arc4random_uniform((uint32_t)n)]);
}

/*
 * Next filler line for a stalling multiline reply.  The banner and the
 * goodbye both use gen_left as their counter, so gen_idx is free to
 * remember what we said last and avoid repeating it back to back.
 */
static const char *
stall_next(struct conn *c)
{
	unsigned n = (unsigned)NITEMS(stall_msgs);
	unsigned k = arc4random_uniform(n);

	if (k == c->gen_idx)
		k = (k + 1) % n;
	c->gen_idx = (uint16_t)k;
	return (stall_msgs[k]);
}

static void
rfc822_date(char *buf, size_t len)
{
	static const char *dow[] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	};
	static const char *mon[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	struct tm tm;

	/* gmtime avoids touching /etc/localtime, which we may not have. */
	gmtime_r(&tp_now, &tm);
	snprintf(buf, len, "%s, %d %s %d %02d:%02d:%02d +0000",
	    dow[tm.tm_wday % 7], tm.tm_mday, mon[tm.tm_mon % 12],
	    tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ------------------------------------------------------------ base64 in */

static int
b64val(unsigned char ch)
{

	if (ch >= 'A' && ch <= 'Z')
		return (ch - 'A');
	if (ch >= 'a' && ch <= 'z')
		return (ch - 'a' + 26);
	if (ch >= '0' && ch <= '9')
		return (ch - '0' + 52);
	if (ch == '+')
		return (62);
	if (ch == '/')
		return (63);
	return (-1);
}

/*
 * Decode what a bot offered as credentials.  NUL separators (SASL PLAIN)
 * become '/', anything unprintable becomes '?'; the result is safe to log.
 */
static void
b64_decode(const char *in, char *out, size_t olen)
{
	uint32_t acc = 0;
	int bits = 0, v;
	size_t o = 0;

	for (; *in != '\0' && o + 1 < olen; in++) {
		if (*in == '=' || *in == ' ' || *in == '\t')
			continue;
		if ((v = b64val((unsigned char)*in)) < 0)
			continue;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			unsigned char ch;

			bits -= 8;
			ch = (unsigned char)((acc >> bits) & 0xff);
			if (ch == '\0')
				ch = '/';
			else if (ch < 0x20 || ch >= 0x7f)
				ch = '?';
			out[o++] = (char)ch;
		}
	}
	out[o] = '\0';
}

/* ----------------------------------------------------------- generators */

static void
gen_banner(struct conn *c)
{

	if (!(c->flags & F_BANNER1)) {
		char date[64];

		c->flags |= F_BANNER1;
		rfc822_date(date, sizeof(date));
		if (c->gen_left != 0) {
			if (c->gen_left != GEN_INF)
				c->gen_left--;
			gen_line(c, "220-%s ESMTP %s; %s", cfg.myname,
			    product(c), date);
			return;
		}
		gen_line(c, "220 %s ESMTP %s; %s", cfg.myname, product(c),
		    date);
		c->gen = G_NONE;
		c->next = S_CMD;
		return;
	}

	if (c->gen_left == 0) {
		gen_line(c, "220 %s ESMTP %s ready", cfg.myname, product(c));
		c->gen = G_NONE;
		c->next = S_CMD;
		return;
	}
	if (c->gen_left != GEN_INF)
		c->gen_left--;
	gen_line(c, "220-%s", stall_next(c));
}

static void
gen_ehlo(struct conn *c)
{
	unsigned nfix = (unsigned)NITEMS(ehlo_exts);
	unsigned itls = 1 + nfix + (unsigned)cfg.ehlo_pad;
	unsigned i = c->gen_idx++;

	if (i == 0) {
		gen_line(c, "250-%s Hello, pleased to meet you", cfg.myname);
		return;
	}
	if (i <= nfix) {
		gen_line(c, "250-%s", ehlo_exts[i - 1]);
		return;
	}
	if (i < itls) {
		/*
		 * Padding.  Unknown extensions must be ignored by the client,
		 * so this is free time on the wire: every line is another few
		 * dozen bytes the sender has to sit through.
		 */
		gen_line(c, "250-X-TARPIT-%04X %08X%08X%08X", i,
		    arc4random(), arc4random(), arc4random());
		return;
	}
	if (i == itls && cfg.tls_stall) {
		gen_line(c, "250-STARTTLS");
		return;
	}
	gen_line(c, "250 HELP");
	c->gen = G_NONE;
	c->next = S_CMD;
}

static void
gen_help(struct conn *c)
{

	if (c->gen_idx < NITEMS(helplines)) {
		gen_line(c, "%s", helplines[c->gen_idx++]);
		return;
	}
	gen_line(c, "214 2.0.0 End of HELP information");
	c->gen = G_NONE;
	c->next = S_CMD;
}

static void
gen_expn(struct conn *c)
{

	/* Address harvesters asked for a list, so give them a long one. */
	if (c->gen_left == 0) {
		gen_line(c, "250 2.0.0 End of list");
		c->gen = G_NONE;
		c->next = S_CMD;
		return;
	}
	if (c->gen_left != GEN_INF)
		c->gen_left--;
	gen_line(c, "250-%s.%s <%s.%s%u@%s>",
	    pick(fake_users, NITEMS(fake_users)),
	    pick(fake_users, NITEMS(fake_users)),
	    pick(fake_users, NITEMS(fake_users)),
	    pick(fake_users, NITEMS(fake_users)),
	    arc4random_uniform(9000) + 1000, cfg.myname);
}

static void
gen_quit(struct conn *c)
{

	if (c->gen_left == 0) {
		gen_line(c, "221 2.0.0 %s closing connection", cfg.myname);
		c->gen = G_NONE;
		c->next = S_CLOSE;
		return;
	}
	if (c->gen_left != GEN_INF)
		c->gen_left--;
	gen_line(c, "221-%s", stall_next(c));
}

/*
 * A TLS handshake that is always just about to finish.  We send a record
 * header and a ServerHello header announcing 16376 bytes of body, then
 * dribble random filler.  The peer's TLS library has committed to reading a
 * complete handshake message before it can do anything at all, so it blocks
 * until its own timeout - typically far longer than its SMTP timeout would
 * have been.
 */
static void
gen_tls(struct conn *c)
{
	static const unsigned char hdr[9] = {
		0x16, 0x03, 0x03, 0x3f, 0xfc,	/* handshake record, 16380 B */
		0x02, 0x00, 0x3f, 0xf8		/* ServerHello, body 16376 B */
	};
	size_t i, n;

	if (c->gen_idx == 0) {		/* still owe them the 220 */
		gen_line(c, "220 2.0.0 Ready to start TLS");
		c->gen_idx = 1;
		return;
	}
	if (c->gen_idx == 1) {		/* start another endless record */
		memcpy(c->out, hdr, sizeof(hdr));
		c->outlen = sizeof(hdr);
		c->outpos = 0;
		c->gen_idx = 16376;
		return;
	}

	n = c->gen_idx < 16 ? c->gen_idx : 16;
	for (i = 0; i < n; i++)
		c->out[i] = (char)arc4random_uniform(256);
	c->outlen = (uint16_t)n;
	c->outpos = 0;
	c->gen_idx -= (uint16_t)n;
	if (c->gen_idx <= 1)
		c->gen_idx = 1;
}

void
tp_refill(struct conn *c)
{

	switch (c->gen) {
	case G_BANNER:
		gen_banner(c);
		break;
	case G_EHLO:
		gen_ehlo(c);
		break;
	case G_HELP:
		gen_help(c);
		break;
	case G_EXPN:
		gen_expn(c);
		break;
	case G_QUIT:
		gen_quit(c);
		break;
	case G_TLS:
		gen_tls(c);
		break;
	default:
		c->gen = G_NONE;
		break;
	}
}

/* -------------------------------------------------------- session start */

void
tp_open(struct conn *c)
{

	c->state = S_BANNER;
	c->next = S_CMD;
	c->gen = G_BANNER;
	c->gen_left = cfg.banner_lines > 0 ?
	    (uint16_t)cfg.banner_lines : GEN_INF;
}

void
tp_early_talker(struct conn *c)
{

	/*
	 * SMTP is server-speaks-first: nothing legitimate transmits before
	 * the final greeting line.  Anything that does is spamware, so it
	 * never gets to see the end of the greeting.
	 */
	c->flags |= F_BADBOT;
	c->gen_left = GEN_INF;
	if (cfg.verbose >= 1)
		tp_log(LOG_INFO, "early talker %s, greeting will not end",
		    c->peer);
}

/* -------------------------------------------------------------- command */

static const char *
angle_addr(const char *s, char *dst, size_t dlen)
{
	const char *lt, *gt;

	if ((lt = strchr(s, '<')) != NULL &&
	    (gt = strchr(lt + 1, '>')) != NULL)
		return (tp_sanitize(dst, dlen, lt + 1, (size_t)(gt - lt - 1)));
	return (tp_sanitize(dst, dlen, s, strlen(s)));
}

static void
cmd_auth(struct conn *c, const char *arg)
{
	char mech[32], safe[128];
	size_t i;

	c->flags |= F_AUTH;
	stats.auths++;

	for (i = 0; i + 1 < sizeof(mech) && arg[i] != '\0' &&
	    !isspace((unsigned char)arg[i]); i++)
		mech[i] = (char)toupper((unsigned char)arg[i]);
	mech[i] = '\0';
	arg += i;
	arg += strspn(arg, " \t");

	c->auth_step = 0;
	if (strcmp(mech, "LOGIN") == 0) {
		c->auth_mech = M_LOGIN;
		respond(c, S_AUTH, "334 VXNlcm5hbWU6");
	} else if (strcmp(mech, "PLAIN") == 0) {
		c->auth_mech = M_PLAIN;
		if (*arg != '\0') {
			char dec[192];

			b64_decode(arg, dec, sizeof(dec));
			if (cfg.logdata)
				tp_log(LOG_NOTICE, "auth %s PLAIN %s", c->peer,
				    tp_sanitize(safe, sizeof(safe), dec,
				    strlen(dec)));
			respond(c, S_CMD,
			    "535 5.7.8 Error: authentication failed: "
			    "generic failure");
		} else
			respond(c, S_AUTH, "334 ");
	} else if (strcmp(mech, "CRAM-MD5") == 0) {
		c->auth_mech = M_CRAMMD5;
		/* An arbitrary but well-formed challenge. */
		respond(c, S_AUTH, "334 PDQxOTI5NDIzNDEuMTI4Mjg0NzJAJXM+");
	} else if (*mech == '\0') {
		respond(c, S_CMD, "501 5.5.4 Syntax: AUTH mechanism");
	} else {
		c->auth_mech = M_OTHER;
		respond(c, S_CMD,
		    "504 5.7.4 Unrecognized authentication type: %s",
		    tp_sanitize(safe, sizeof(safe), mech, strlen(mech)));
	}
}

static void
auth_line(struct conn *c, const char *line)
{
	char dec[192], safe[256];

	if (strcmp(line, "*") == 0) {
		respond(c, S_CMD, "501 5.0.0 Authentication aborted");
		return;
	}
	b64_decode(line, dec, sizeof(dec));

	if (c->auth_mech == M_LOGIN && c->auth_step == 0) {
		if (cfg.logdata)
			tp_log(LOG_NOTICE, "auth %s LOGIN user=%s", c->peer,
			    tp_sanitize(safe, sizeof(safe), dec, strlen(dec)));
		c->auth_step = 1;
		respond(c, S_AUTH, "334 UGFzc3dvcmQ6");
		return;
	}
	if (cfg.logdata)
		tp_log(LOG_NOTICE, "auth %s %s%s", c->peer,
		    c->auth_mech == M_LOGIN ? "LOGIN pass=" : "response=",
		    tp_sanitize(safe, sizeof(safe), dec, strlen(dec)));

	/* Never succeed, never permanently fail: let it keep guessing. */
	respond(c, S_CMD,
	    "535 5.7.8 Error: authentication failed: generic failure");
}

static void
cmd_dispatch(struct conn *c, char *line)
{
	char vb[16], safe[320];
	const char *arg;
	size_t i;

	c->ncmd++;
	stats.cmds++;

	for (i = 0; i + 1 < sizeof(vb) && line[i] != '\0' &&
	    !isspace((unsigned char)line[i]); i++)
		vb[i] = (char)toupper((unsigned char)line[i]);
	vb[i] = '\0';
	arg = line + strcspn(line, " \t");
	arg += strspn(arg, " \t");

	if (cfg.verbose >= 2)
		tp_log(LOG_DEBUG, "cmd %s <%s>", c->peer,
		    tp_sanitize(safe, sizeof(safe), line, strlen(line)));

	if (strcmp(vb, "EHLO") == 0 || strcmp(vb, "LHLO") == 0) {
		if (cfg.logdata && cfg.verbose >= 1)
			tp_log(LOG_INFO, "helo %s ehlo=%s", c->peer,
			    tp_sanitize(safe, sizeof(safe), arg, strlen(arg)));
		c->flags |= F_HELO | F_ESMTP;
		c->gen = G_EHLO;
		c->gen_idx = 0;
		c->state = S_RESP;
		c->next = S_CMD;
		tp_refill(c);
		return;
	}
	if (strcmp(vb, "HELO") == 0) {
		if (cfg.logdata && cfg.verbose >= 1)
			tp_log(LOG_INFO, "helo %s helo=%s", c->peer,
			    tp_sanitize(safe, sizeof(safe), arg, strlen(arg)));
		c->flags |= F_HELO;
		respond(c, S_CMD, "250 %s Hello, pleased to meet you",
		    cfg.myname);
		return;
	}
	if (strcmp(vb, "MAIL") == 0) {
		char addr[256];

		angle_addr(arg, addr, sizeof(addr));
		if (cfg.logdata && cfg.verbose >= 1)
			tp_log(LOG_INFO, "mail %s from=<%s>", c->peer, addr);
		c->flags |= F_MAIL;
		c->nrcpt = 0;
		respond(c, S_CMD,
		    "250 2.1.0 <%s>... Sender ok, message will be scanned "
		    "before delivery", addr);
		return;
	}
	if (strcmp(vb, "RCPT") == 0) {
		char addr[256];

		if (!(c->flags & F_MAIL)) {
			respond(c, S_CMD, "503 5.5.1 Error: need MAIL command");
			return;
		}
		angle_addr(arg, addr, sizeof(addr));
		if (cfg.logdata && cfg.verbose >= 1)
			tp_log(LOG_INFO, "rcpt %s to=<%s>", c->peer, addr);
		if (c->nrcpt >= (uint16_t)cfg.maxrcpt) {
			respond(c, S_CMD,
			    "452 4.5.3 Too many recipients, please retry later");
			return;
		}
		c->nrcpt++;
		respond(c, S_CMD,
		    "250 2.1.5 <%s>... Recipient ok, delivery may be delayed",
		    addr);
		return;
	}
	if (strcmp(vb, "DATA") == 0) {
		if (c->nrcpt == 0) {
			respond(c, S_CMD, "503 5.5.1 Error: need RCPT command");
			return;
		}
		c->dstate = 0;
		c->flags |= F_DATA;
		respond(c, S_DATA,
		    "354 Enter mail, end with \".\" on a line by itself");
		return;
	}
	if (strcmp(vb, "BDAT") == 0) {
		unsigned long long sz;
		char *end;

		if (c->nrcpt == 0) {
			respond(c, S_CMD, "503 5.5.1 Error: need RCPT command");
			return;
		}
		sz = strtoull(arg, &end, 10);
		if (end == arg) {
			respond(c, S_CMD, "501 5.5.4 Syntax: BDAT size [LAST]");
			return;
		}
		end += strspn(end, " \t");
		c->bdat_left = sz;
		c->flags |= F_DATA;
		if (strncasecmp(end, "LAST", 4) == 0)
			c->flags |= F_BDATLAST;
		else
			c->flags &= (uint16_t)~F_BDATLAST;
		if (sz == 0) {
			respond(c, S_CMD, "%s",
			    pick(tempfails, NITEMS(tempfails)));
			return;
		}
		c->state = S_BDAT;
		c->next = S_BDAT;
		c->outlen = c->outpos = 0;
		return;
	}
	if (strcmp(vb, "STARTTLS") == 0) {
		if (!cfg.tls_stall) {
			respond(c, S_CMD, "454 4.7.0 TLS not available now");
			return;
		}
		stats.tlss++;
		if (cfg.verbose >= 1)
			tp_log(LOG_INFO, "starttls %s entering handshake stall",
			    c->peer);
		c->flags |= F_TLS;
		c->gen = G_TLS;
		c->gen_idx = 0;
		c->state = S_TLS;
		c->next = S_TLS;
		tp_refill(c);
		return;
	}
	if (strcmp(vb, "AUTH") == 0) {
		cmd_auth(c, arg);
		return;
	}
	if (strcmp(vb, "RSET") == 0) {
		c->flags &= (uint16_t)~(F_MAIL | F_DATA);
		c->nrcpt = 0;
		respond(c, S_CMD, "250 2.0.0 Reset state");
		return;
	}
	if (strcmp(vb, "NOOP") == 0) {
		respond(c, S_CMD, "250 2.0.0 Ok");
		return;
	}
	if (strcmp(vb, "VRFY") == 0) {
		respond(c, S_CMD,
		    "252 2.5.2 Cannot VRFY user, but will accept message "
		    "and attempt delivery");
		return;
	}
	if (strcmp(vb, "EXPN") == 0) {
		c->gen = G_EXPN;
		c->gen_left = 32;
		c->state = S_RESP;
		c->next = S_CMD;
		tp_refill(c);
		return;
	}
	if (strcmp(vb, "HELP") == 0) {
		c->gen = G_HELP;
		c->gen_idx = 0;
		c->state = S_RESP;
		c->next = S_CMD;
		tp_refill(c);
		return;
	}
	if (strcmp(vb, "QUIT") == 0) {
		c->gen = G_QUIT;
		c->gen_left = cfg.quit_hang ? GEN_INF : 0;
		c->state = S_RESP;
		c->next = S_CLOSE;
		tp_refill(c);
		return;
	}
	if (strcmp(vb, "ETRN") == 0) {
		respond(c, S_CMD, "458 4.3.0 Unable to queue messages for node");
		return;
	}
	if (*vb == '\0') {
		respond(c, S_CMD, "500 5.5.2 Error: bad syntax");
		return;
	}
	respond(c, S_CMD, "500 5.5.2 Error: command not recognized: %s",
	    tp_sanitize(safe, sizeof(safe), vb, strlen(vb)));
}

/* ---------------------------------------------------------------- input */

static void
body_done(struct conn *c)
{

	stats.msgs++;
	if (cfg.verbose >= 1)
		tp_log(LOG_INFO, "body %s swallowed %llu bytes, tempfailing",
		    c->peer, (unsigned long long)(c->dbytes - c->dmark));
	c->dmark = c->dbytes;
	c->nrcpt = 0;
	c->flags &= (uint16_t)~F_MAIL;
	respond(c, S_CMD, "%s", pick(tempfails, NITEMS(tempfails)));
}

static void
feed_cmd(struct conn *c, unsigned char ch)
{

	if (ch == '\r')
		return;
	if (ch == '\n') {
		c->line[c->linelen] = '\0';
		if (c->flags & F_OVERLONG) {
			c->flags &= (uint16_t)~F_OVERLONG;
			c->linelen = 0;
			respond(c, S_CMD, "500 5.5.2 Line too long");
			return;
		}
		c->linelen = 0;
		if (c->state == S_AUTH)
			auth_line(c, c->line);
		else
			cmd_dispatch(c, c->line);
		return;
	}
	if (c->linelen < TP_LINEMAX - 1)
		c->line[c->linelen++] = (char)ch;
	else
		c->flags |= F_OVERLONG;
}

/* Matches the CRLF.CRLF (and bare-LF) end of a DATA body. */
static void
feed_data(struct conn *c, unsigned char ch)
{

	c->dbytes++;
	switch (c->dstate) {
	case 0:					/* start of a line */
		if (ch == '.')
			c->dstate = 1;
		else if (ch != '\n')
			c->dstate = 2;
		break;
	case 1:					/* saw a leading dot */
		if (ch == '\r')
			c->dstate = 3;
		else if (ch == '\n')
			body_done(c);
		else
			c->dstate = 2;
		break;
	case 2:					/* middle of a line */
		if (ch == '\n')
			c->dstate = 0;
		break;
	case 3:					/* saw dot CR */
		if (ch == '\n')
			body_done(c);
		else if (ch == '\r')
			c->dstate = 3;
		else
			c->dstate = 2;
		break;
	}
}

void
tp_input(struct conn *c, const unsigned char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		switch (c->state) {
		case S_CMD:
		case S_AUTH:
			feed_cmd(c, buf[i]);
			break;
		case S_DATA:
			feed_data(c, buf[i]);
			break;
		case S_BDAT:
			c->dbytes++;
			if (c->bdat_left > 0 && --c->bdat_left == 0) {
				if (c->flags & F_BDATLAST)
					body_done(c);
				else
					respond(c, S_CMD,
					    "250 2.0.0 Ok: chunk received");
			}
			break;
		default:
			/* Output is pending; anything they send can wait. */
			return;
		}
		/*
		 * A reply was queued: stop consuming, so a pipelining client
		 * finds the rest of its batch still sitting in our tiny
		 * receive buffer with the window slammed shut.
		 */
		if (c->outpos < c->outlen || c->gen != G_NONE)
			return;
	}
}
