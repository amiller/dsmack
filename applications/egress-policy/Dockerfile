FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --chmod=0555 gateway /gateway
COPY --chmod=0444 probe.py /probe.py
USER 65532:65532
ENTRYPOINT ["/gateway"]
