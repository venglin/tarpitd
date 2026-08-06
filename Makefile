# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Przemyslaw Frasunek <przemyslaw@frasunek.com>
#
# tarpitd - an SMTP tarpit for FreeBSD
#
# Build and install with the base system's make(1):
#
#	make && make install
#
# Optional knobs:
#
#	make WITH_CAPSICUM=yes		sandbox the workers with capsicum(4)
#	make DEBUG=yes			-O0 -g, no optimisation
#	make NO_RCD=yes			skip the rc.d script (the port
#					installs its own via USE_RC_SUBR)
#

PROG=		tarpitd
SRCS=		tarpitd.c smtp.c
MAN=		tarpitd.8

PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/share/man/man
RCDIR?=		${PREFIX}/etc/rc.d

CFLAGS+=	-std=c99 -Wall -Wextra -Wno-unused-parameter
CFLAGS+=	-D_BSD_SOURCE

.if defined(DEBUG)
CFLAGS+=	-O0 -g -fno-omit-frame-pointer
.else
CFLAGS+=	-O2 -pipe
.endif

.if defined(WITH_CAPSICUM)
CFLAGS+=	-DWITH_CAPSICUM
.endif

# pidfile(3).  Spelled as LDADD rather than LIBADD because this is an
# out-of-tree build, where bsd.libnames.mk only converts LIBADD with a warning.
LDADD=		-lutil

# bsd.prog.mk knows nothing about rc.d, so install the script here.  The
# FreeBSD port sets NO_RCD and installs its own copy through USE_RC_SUBR,
# which substitutes %%PREFIX%% and registers the file in the package list.
CLEANFILES+=	tarpitd.rc

# bsd.prog.mk expects its target directories to exist already, which is true
# of the base system but not of an empty DESTDIR such as a port's stage tree.
beforeinstall:
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -d ${DESTDIR}${MANDIR}8

.if !defined(NO_RCD)
afterinstall: tarpitd.rc
	${INSTALL} -d ${DESTDIR}${RCDIR}
	${INSTALL} -m 555 tarpitd.rc ${DESTDIR}${RCDIR}/tarpitd

tarpitd.rc: ${.CURDIR}/rc.d/tarpitd
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}
.endif

.include <bsd.prog.mk>
