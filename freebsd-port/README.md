# FreeBSD port

The port skeleton for `mail/tarpitd`, kept here so that it is versioned
alongside the source it packages. It was added after the `v1.0.0` tag, so it
is not part of the distfile.

```
mail/tarpitd/Makefile          port makefile
mail/tarpitd/distinfo          distfile checksum, regenerate with make makesum
mail/tarpitd/pkg-descr         package description
mail/tarpitd/files/tarpitd.in  rc.d script, fed to USE_RC_SUBR
tarpitd-port.diff              ready to attach to a Bugzilla PR
```

`files/tarpitd.in` is a copy of `../rc.d/tarpitd`. Both carry `%%PREFIX%%`:
upstream substitutes it with sed at install time, the port lets `USE_RC_SUBR`
do it. **Keep the two in sync** when changing the startup script.

## Installing into a ports tree

```sh
cp -R mail/tarpitd /usr/ports/mail/
cd /usr/ports/mail && \
    sed -i '' -e '/SUBDIR += t-prot$/a\
    SUBDIR += tarpitd
' Makefile
```

## Validating before submitting

```sh
cd /usr/ports/mail/tarpitd
make makesum                      # after every new upstream release
make BATCH=yes stage
make BATCH=yes check-plist
env DEVELOPER=yes make BATCH=yes stage-qa
portlint -A                       # needs the files git-added in the ports tree
make BATCH=yes package
```

`BATCH=yes` matters: without it the `CAPSICUM` option opens a dialog and the
build waits for input.

## Submitting

Attach `tarpitd-port.diff` to a new bug at
<https://bugs.freebsd.org/bugzilla/>, product *Ports & Packages*, component
*Individual Port(s)*, with `[NEW PORT] mail/tarpitd` in the summary and
`maintainer-feedback?` left unset (you are the maintainer). Regenerate the
diff after any change:

```sh
cd /usr/ports && git add mail/tarpitd mail/Makefile && \
    git diff --cached mail/ > tarpitd-port.diff
```

## Updating for a new release

1. Tag and release upstream.
2. Bump `DISTVERSION` in `mail/tarpitd/Makefile`; reset `PORTREVISION` if set.
3. `make makesum`, then revalidate as above.
