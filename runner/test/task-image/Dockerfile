# Test task image for the runner's task API (test/run_tests.sh). COPY only, so an amd64 host builds it for arm64.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY entry.sh /entry.sh
ENTRYPOINT ["/bin/sh", "/entry.sh"]
