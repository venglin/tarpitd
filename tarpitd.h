/*-
 * tarpitd - an SMTP tarpit daemon for FreeBSD
 *
 * Shared declarations between the event loop (tarpitd.c) and the
 * SMTP dialogue state machine (smtp.c).
 */

#ifndef TARPITD_H
#define TARPITD_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdarg.h>
#include <stdint.h>
#include <time.h>

#define TP_LINEMAX	512	/* longest command line we retain */
#define TP_OUTMAX	256	/* one response line at a time */
#define TP_PEERMAX	72	/* "addr:port -> addr:port" */

#define GEN_INF		0xffffu	/* generator never stops */

/* First member of every kevent udata payload, so we can tell them apart. */
enum tp_kind {
	K_LISTENER = 1,
	K_CONN
};

/* What the connection is doing right now. */
enum tp_state {
	S_BANNER = 0,	/* dribbling the multiline greeting */
	S_RESP,		/* dribbling a response */
	S_CMD,		/* reading a command line, one byte at a time */
	S_DATA,		/* swallowing a message body */
	S_BDAT,		/* swallowing a BDAT chunk */
	S_AUTH,		/* reading one leg of an AUTH exchange */
	S_TLS,		/* emitting a TLS handshake that never completes */
	S_CLOSE		/* hang up once the output buffer drains */
};

/* Multiline output generators; they refill c->out one line per tick. */
enum tp_gen {
	G_NONE = 0,
	G_BANNER,
	G_EHLO,
	G_HELP,
	G_EXPN,
	G_QUIT,
	G_TLS
};

enum tp_flags {
	F_BADBOT	= 0x0001,	/* talked before the greeting finished */
	F_BANNER1	= 0x0002,	/* first banner line already emitted */
	F_HELO		= 0x0004,
	F_ESMTP		= 0x0008,
	F_MAIL		= 0x0010,
	F_DATA		= 0x0020,	/* reached DATA at least once */
	F_OVERLONG	= 0x0040,	/* command line was truncated */
	F_TLS		= 0x0080,	/* tried STARTTLS */
	F_AUTH		= 0x0100,	/* tried AUTH */
	F_BDATLAST	= 0x0200	/* current BDAT chunk was flagged LAST */
};

enum tp_mech {
	M_NONE = 0,
	M_PLAIN,
	M_LOGIN,
	M_CRAMMD5,
	M_OTHER
};

struct ipent;

struct conn {
	int		kind;		/* K_CONN */
	int		fd;
	LIST_ENTRY(conn) link;
	struct ipent	*ipe;		/* per-source-address refcount */

	uint8_t		state;		/* enum tp_state */
	uint8_t		next;		/* state to enter once output drains */
	uint8_t		gen;		/* enum tp_gen */
	uint8_t		dstate;		/* CRLF.CRLF matcher */
	uint8_t		auth_step;
	uint8_t		auth_mech;	/* enum tp_mech */
	uint8_t		prod;		/* which MTA we pretend to be */
	uint8_t		eof;		/* peer sent FIN */

	uint16_t	flags;		/* enum tp_flags */
	uint16_t	gen_left;	/* lines still to emit, or GEN_INF */
	uint16_t	gen_idx;	/* generator cursor */
	uint16_t	linelen;
	uint16_t	outlen;
	uint16_t	outpos;
	uint16_t	nrcpt;

	uint32_t	ncmd;
	uint64_t	rx;		/* bytes read off the wire */
	uint64_t	tx;		/* bytes written */
	uint64_t	dbytes;		/* bytes of message body swallowed */
	uint64_t	dmark;		/* dbytes at the end of the last message */
	uint64_t	bdat_left;	/* BDAT octets still expected */

	time_t		start;

	char		line[TP_LINEMAX];
	char		out[TP_OUTMAX];
	char		peer[TP_PEERMAX];
};

struct tp_cfg {
	const char	*myname;	/* hostname we announce */
	int		verbose;
	int		foreground;
	int		maxconn;
	int		maxperip;	/* 0 = unlimited */
	int		workers;
	int		chunk;		/* bytes per read/write tick */
	int		drip_ms;	/* initial delay between ticks */
	int		maxdrip_ms;	/* ceiling after ramping */
	int		ramp_s;		/* double the delay every N seconds */
	int		greet_s;	/* silence before the first banner byte */
	int		banner_lines;	/* 0 = never finish the greeting */
	int		ehlo_pad;	/* bogus EHLO extensions to add */
	int		maxsess_s;	/* hard session cap, 0 = unlimited */
	int		sockbuf;	/* SO_RCVBUF/SO_SNDBUF, 0 = leave alone */
	int		logdata;	/* log envelopes and credentials */
	int		quit_hang;	/* ignore QUIT and keep dribbling */
	int		tls_stall;	/* advertise STARTTLS and stall it */
	int		maxrcpt;
};

struct tp_stats {
	uint64_t	conns;		/* accepted */
	uint64_t	refused;	/* over the per-IP limit */
	uint64_t	rx;
	uint64_t	tx;
	uint64_t	cmds;
	uint64_t	msgs;		/* bodies swallowed to the final dot */
	uint64_t	auths;
	uint64_t	tlss;
	uint64_t	wasted;		/* connection-seconds burnt */
	uint32_t	cur;
	uint32_t	peak;
};

extern struct tp_cfg	cfg;
extern struct tp_stats	stats;
extern time_t		tp_now;

/* tarpitd.c */
void	tp_log(int pri, const char *fmt, ...) __printflike(2, 3);
void	tp_conn_close(struct conn *c, const char *why);
char	*tp_sanitize(char *dst, size_t dlen, const char *src, size_t slen);

/* smtp.c */
void	tp_open(struct conn *c);
void	tp_refill(struct conn *c);
void	tp_input(struct conn *c, const unsigned char *buf, size_t n);
void	tp_early_talker(struct conn *c);

#endif /* TARPITD_H */
