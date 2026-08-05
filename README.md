# tarpitd

An SMTP tarpit for FreeBSD, in the spirit of OpenBSD's `spamd(8)`, that holds
known spam sources on the wire for as long as they can be persuaded to wait.

Nothing is ever accepted and nothing is ever permanently rejected: every
terminal answer is a `4xx`, so the message stays in the sender's queue and
comes back to us later. The goal is not to reject mail quickly — it is to
occupy a slot in the sending botnet's delivery queue for hours.

## tarpitd does not decide who is a spammer

**The IP addresses come from an external source.** `tarpitd` has no blocklist,
no scoring, no heuristics and no opinion about who is connecting; it simply
answers whatever arrives on its port, very slowly. Deciding whose traffic gets
redirected to it is entirely the job of whatever populates your firewall table
— `fail2ban`, `blacklistd(8)`, a DNSBL feed, a script of your own, or a table
you maintain by hand.

This is the main difference from `spamd(8)`, which ships with its own list
handling. Here the two concerns are deliberately separate: your existing
classifier keeps producing addresses, and `tarpitd` is only the thing that
punishes them.

The setup this was written for: `fail2ban` watches the mail log, and on
matching a rule adds the offending address to an IPFW table; one `ipfw fwd`
rule redirects everything from that table to the tarpit.

## How it works

The whole trick is being **slow but correct**. Every reply is syntactically
valid SMTP, so the sender has no reason to hang up — it just arrives one byte
at a time, and commands are read back at the same rate.

| Tactic | What it does |
|---|---|
| Greeting delay | Nothing at all is sent for `-g` seconds after the connection is accepted. |
| Stuttering | One byte every `-S` ms in each direction. The peer's send buffer never drains, so it blocks in `write()`. |
| Endless greeting | A multiline `220-` banner. An RFC-conforming client **must** wait for the final `220 ` line, and with `-b 0` that line never comes. |
| Early talker detection | SMTP is server-speaks-first, so nothing legitimate transmits before the greeting ends. Anything that does gets the endless banner and double delays. |
| Extension bloat | `-e` extra unknown extensions in the `EHLO` reply, which a client must read and then ignore. |
| TLS stall | A TLS record header announcing a 16376-byte `ServerHello`, followed by dribbled random filler. The peer's TLS library has committed to reading a complete handshake message before it can do anything else — including time out at the SMTP layer. When one record finishes, the next one starts. |
| AUTH honeypot | Offers `PLAIN`/`LOGIN`/`CRAM-MD5`, base64-decodes what the bot sends, logs it, and answers `535` so it keeps guessing. |
| Tiny TCP window | `SO_RCVBUF`/`SO_SNDBUF` clamped to `-w` bytes, so the peer only ever has a few hundred bytes in flight. This is also what keeps kernel memory per session small. |
| Backlog parking | At `-c` connections we stop calling `accept()` instead of refusing. The excess sits in the kernel listen queue — the sender believes it is connected, and it costs us no descriptors at all. |
| Delay ramping | The delay doubles every `-R` seconds up to `-M`. A peer that has already waited an hour is patient and can be held almost for free. All delays are jittered so the timing is not a fingerprint. |

At the defaults (one byte per 1.5 s), the `EHLO` reply alone takes about
40 minutes and a full delivery attempt takes hours.

## Building and installing

```sh
make
make install          # /usr/local/sbin/tarpitd + man page + rc.d script
```

Optional:

```sh
make WITH_CAPSICUM=yes   # workers enter capability mode after bind()
make DEBUG=yes
```

Nothing outside the base system is required (`kqueue`, `libutil`).

## ipfw

Assuming your classifier fills table 22, redirect it to the tarpit:

```sh
ipfw table 22 create type addr        # if it does not exist yet
ipfw add 1000 fwd 127.0.0.1,8025 tcp from "table(22)" to me 25 in
```

An `ipfw fwd` rule with a local address delivers the packet locally on the
given port without rewriting the headers, so `getsockname()` inside tarpitd
still sees the **original destination**. That is why each logged session
records which of your addresses the bot was aiming at.

For IPv6:

```sh
ipfw add 1001 fwd ::1,8025 tcp from "table(22)" to me6 25 in
tarpitd -l 127.0.0.1:8025 -l "[::1]:8025"
```

Check that `net.inet.ip.fw.one_pass` does not upset the rest of your ruleset —
with `one_pass=1` (the default) a packet does not return to later rules after
`fwd`.

Enabling the service:

```sh
sysrc tarpitd_enable=YES
sysrc tarpitd_maxconn=8192
service tarpitd start
```

rc.conf variables:

| Variable | Default | Meaning |
|---|---|---|
| `tarpitd_enable` | `NO` | |
| `tarpitd_listen` | `127.0.0.1:8025` | listen address |
| `tarpitd_maxconn` | `4096` | concurrent session limit |
| `tarpitd_runas` | `nobody` | user to drop privileges to |
| `tarpitd_pidfile` | `/var/run/tarpitd.pid` | |
| `tarpitd_flags` | — | extra options, e.g. `-v` |

**The user is `tarpitd_runas`, not `tarpitd_user`.** `${name}_user` is reserved
by `rc.subr` and makes it run the whole thing under `su`, which leaves the
daemon unable to write its pidfile or bind a privileged port, and its own
privilege drop then fails in `setgroups()` with `EPERM`.

Watching it live, without detaching:

```sh
tarpitd -d -v -v -l 127.0.0.1:8025 -u ""
```

## Kernel tuning for thousands of held connections

Every captured connection is a descriptor and a socket for hours. For
`-c 8192`, in `/etc/sysctl.conf`:

```
kern.ipc.maxsockets=65536
kern.maxfiles=131072
net.inet.tcp.syncache.hashsize=2048
net.inet.tcp.syncache.bucketlimit=100
```

The rc.d script raises the process descriptor limit to `tarpitd_maxconn + 128`
by itself. If the hard limit does not allow that, the daemon lowers `-c` and
says so in the log.

Leave `net.inet.tcp.blackhole=0` for the tarpit's port — the handshake has to
succeed, or there is nobody to hold.

## Statistics

`SIGINFO` (Ctrl-T on a terminal) or `SIGHUP` writes a summary; the same line
goes to syslog once an hour:

```
stats: active=1832 peak=2140 total=41991 refused=88 wasted=3106h12m \
       bodies=903 auth=2214 tls=771 cmds=88410 rx=1104882 tx=48221904
```

`wasted` is the total connection time burnt — the only metric that matters here.

## Logging

With `-v`, session open/close with a summary, envelopes and harvested
credentials go to syslog (facility `mail`):

```
open 203.0.113.9:41022>198.51.100.4:25 (312 active)
early talker 203.0.113.9:41022>198.51.100.4:25, greeting will not end
mail 203.0.113.9:41022>198.51.100.4:25 from=<bounce@spam.example>
auth 203.0.113.9:41022>198.51.100.4:25 LOGIN user=admin
auth 203.0.113.9:41022>198.51.100.4:25 LOGIN pass=P@ssw0rd123
starttls 203.0.113.9:41022>198.51.100.4:25 entering handshake stall
close 203.0.113.9:41022>198.51.100.4:25 held=27431s cmds=14 rcpt=3 body=0 \
      rx=241 tx=39122 early-talker (session limit)
```

(Addresses above are RFC 5737 documentation ranges.)

Everything received from the remote side is sanitised before being written, so
there are no control characters and no log injection. `-L` turns off logging of
envelopes and credentials if you would rather not keep them.

## Warning

Do not send traffic here that you have not already classified as hostile.
`tarpitd` is indistinguishable from a badly broken mail server: a legitimate
sender that ends up in it will retry until its queue lifetime expires and then
bounce the message back to its user.

## Layout

```
tarpitd.c     kqueue event loop, sockets, limits, privileges, workers
smtp.c        SMTP dialogue state machine and reply generators
tarpitd.h     shared declarations
rc.d/tarpitd  startup script
tarpitd.8     manual page
```

## Licence

BSD-2-Clause. See [LICENSE](LICENSE).
