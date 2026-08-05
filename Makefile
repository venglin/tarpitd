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
#

PROG=		tarpitd
SRCS=		tarpitd.c smtp.c
MAN=		tarpitd.8

BINDIR?=	/usr/local/sbin
MANDIR?=	/usr/local/share/man/man

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

# rc.d script is not installed by bsd.prog.mk; do it here.
afterinstall:
	${INSTALL} -d ${DESTDIR}/usr/local/etc/rc.d
	${INSTALL} -m 555 ${.CURDIR}/rc.d/tarpitd \
	    ${DESTDIR}/usr/local/etc/rc.d/tarpitd

.include <bsd.prog.mk>
