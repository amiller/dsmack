FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN sed -i 's|http://deb.debian.org/\(debian[a-z-]*\)|http://snapshot.debian.org/archive/\1/20261123T000000Z|' /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends podman crun conmon ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/* \
 && useradd -u 1000 -m dev && : > /etc/subuid && : > /etc/subgid
COPY containers.conf storage.conf run.sh /opt/dev/
ENV HOME=/workspace XDG_RUNTIME_DIR=/workspace/run CONTAINERS_CONF=/opt/dev/containers.conf \
    CONTAINERS_STORAGE_CONF=/opt/dev/storage.conf TMPDIR=/var/lib/dsmack-engine/tmp
