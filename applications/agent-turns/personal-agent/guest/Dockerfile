# Build from the repository root: docker buildx build -f applications/agent-turns/personal-agent/guest/Dockerfile .
FROM alpine:3.22
RUN apk add --no-cache python3 py3-cryptography
COPY dstack-compat/dsmack_dstack.py applications/agent-turns/personal-agent/guest/agent_turn.py /opt/turn/
