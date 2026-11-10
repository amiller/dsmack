FROM --platform=linux/arm64 debian:trixie-slim AS proot-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libtalloc-dev curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/proot-me/proot/archive/refs/tags/v5.4.0.tar.gz \
 | tar -xz -C /tmp \
 && make -C /tmp/proot-5.4.0/src -j2

FROM --platform=linux/arm64 debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-cryptography libtalloc2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=proot-build /tmp/proot-5.4.0/src/proot /usr/bin/proot
COPY --chmod=0755 loader.py /opt/encrypted/loader.py
COPY --chmod=0444 payload.aes /opt/encrypted/payload.aes
ENTRYPOINT ["/opt/encrypted/loader.py"]
