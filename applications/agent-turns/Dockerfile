# Build on the operator host. QUALIFIED_CLAUDE_REPOSITORY is a local name for the qualified source image.
ARG QUALIFIED_CLAUDE_REPOSITORY
FROM --platform=linux/arm64 ${QUALIFIED_CLAUDE_REPOSITORY}@sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418
USER root
COPY find.py /opt/agent-turns/find.py
RUN chmod 0444 /opt/agent-turns/find.py \
 && printf '%s  %s\n' b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2 /usr/local/bin/claude | sha256sum -c -
USER 1000:1000
ENTRYPOINT ["/usr/bin/python3", "/opt/agent-turns/find.py"]
