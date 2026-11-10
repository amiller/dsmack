#!/bin/bash
# Same unencrypted #fractal-ops room and on-host Hermes credentials as XHS.
set -eu
HERMES_ENV=${HERMES_ENV:-$HOME/.hermes-3090/.env}
set -a
. "$HERMES_ENV"
set +a
: "${MATRIX_HOMESERVER:?}"
: "${MATRIX_ACCESS_TOKEN:?}"
room=$(printf '%s' '!TJdMlOQ4b7gpkOmtKLUGA0525FUxl9EZXLbnTsCIgK4' | jq -sRr @uri)
curl -sf -X PUT \
  "$MATRIX_HOMESERVER/_matrix/client/v3/rooms/$room/send/m.room.message/dsmack$(date +%s%N)" \
  -H "Authorization: Bearer $MATRIX_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg b "$1" '{msgtype:"m.text",body:$b}')" >/dev/null
