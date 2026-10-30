FROM --platform=linux/arm64 node:24.22.1-bookworm-slim
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 git bash curl ca-certificates iproute2 ripgrep \
 && rm -rf /var/lib/apt/lists/* \
 && usermod -l agent -d /workspace node
WORKDIR /opt/compute-node
COPY applications/compute-node/package.json applications/compute-node/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY applications/compute-node/dsmack-compute /usr/local/bin/dsmack-compute
COPY applications/compute-node/agent-mcp.mjs applications/compute-node/pi-tools.mjs ./
COPY applications/compute-node/dsmack-egress /usr/local/bin/dsmack-egress
RUN chmod 0755 /usr/local/bin/dsmack-compute /usr/local/bin/dsmack-egress \
 && chmod -R a+rX /opt/compute-node \
 && chmod 0700 /root \
 && ln -s /dev/shm /run/dsmack
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/dsmack-compute"]
