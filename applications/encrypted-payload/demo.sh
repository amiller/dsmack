#!/bin/sh
set -eu
answer=$({ printf '%s:%s:' "$PAYLOAD_DOMAIN" "$1"; cat marker; } | sha256sum)
answer=${answer%% *}
printf '{"derived_sha256":"%s"}\n' "$answer" | tee /outputs/answer.json
