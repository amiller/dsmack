# Build on the operator host from the repository root (mac.py image). QUALIFIED_CLAUDE_REPOSITORY names the qualified
# source image, which the build reads from a local OCI layout.
ARG QUALIFIED_CLAUDE_REPOSITORY
FROM --platform=linux/arm64 ${QUALIFIED_CLAUDE_REPOSITORY}@sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418
USER root
COPY applications/agent-turns/find.py applications/agent-turns/sentinel_env.py /opt/agent-turns/
COPY base-vm/browser-sandbox-v1/source/guest/sentinel/harness /opt/sentinel/harness
RUN chmod -R a=rX /opt/agent-turns /opt/sentinel && test -f /etc/ssl/certs/ca-certificates.crt \
 && printf '%s  %s\n' b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2 /usr/local/bin/claude | sha256sum -c -
USER 1000:1000
ENTRYPOINT ["/usr/bin/python3", "/opt/agent-turns/find.py"]
