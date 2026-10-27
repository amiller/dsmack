ARG QUALIFIED_CLAUDE_REPOSITORY
FROM --platform=linux/arm64 ${QUALIFIED_CLAUDE_REPOSITORY}@sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418
USER root
COPY applications/compute-node/dsmack-compute /usr/local/bin/dsmack-compute
COPY applications/compute-node/worker.py /opt/compute-node/worker.py
COPY applications/agent-turns/find.py /opt/agent-turns/find.py
COPY base-vm/browser-sandbox-v1/source/guest/sentinel/ /opt/sentinel/
RUN ln -s /dev/shm /run/dsmack && printf '%s  %s\n' b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2 /usr/local/bin/claude | sha256sum -c -
ENTRYPOINT ["/usr/local/bin/dsmack-compute"]
