#!/usr/bin/env bash
# Run one turn on the mini from the laptop: fetch the current head's compose from the coordinator
# (forwarded to 127.0.0.1:19471), boot the installed mac-compose Runner.app with --attest, and fetch its outputs.
# usage: run_turn.sh LABEL LOCAL_OUT
set -euo pipefail
LABEL=$1 OUT=$2
R=personal-agent-turns-20261025 APP=personal-agent-turns-20261025
curl -sf http://127.0.0.1:19471/compose/$APP | ssh mini-mesh "cat > ~/$R/compose-$LABEL.json"
ssh mini-mesh "cd ~/$R && open -n -W --stderr \$PWD/runner-$LABEL.log ~/vz-runner/runner/build/Runner.app --args run \
  --compose \$PWD/compose-$LABEL.json --app $APP --out \$PWD/out-$LABEL --base \$PWD/base \
  --kms http://127.0.0.1:19471/turn --oci-archive \$PWD/turn.oci.tar --attest; tail -5 runner-$LABEL.log"
mkdir -p "$OUT"
ssh mini-mesh "cd ~/$R && tar cf - runner-$LABEL.log compose-$LABEL.json out-$LABEL" | tar xf - -C "$OUT"
