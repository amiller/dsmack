FROM debian:trixie-20260713-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
RUN printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260721T000000Z trixie main\n' \
      > /etc/apt/sources.list.d/99-snapshot-http.list \
    && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.sources \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm /etc/apt/sources.list.d/99-snapshot-http.list \
    && printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260721T000000Z trixie main\n' \
      > /etc/apt/sources.list.d/99-snapshot.list \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       debootstrap \
       crossbuild-essential-arm64 \
       bc bison flex libssl-dev libelf-dev dwarves make gcc \
       cpio pax-utils squashfs-tools cryptsetup \
       xz-utils kmod python3 curl rsync file gawk patch tar gzip jq busybox-static e2fsprogs \
    && rm -rf /var/lib/apt/lists/*
