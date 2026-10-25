#!/usr/bin/env bash
# Run one turn on the mini from the laptop: copy compose-turn-N.json from the keeper's state on
# zed to the mini, boot the installed mac-compose Runner.app with --attest, and fetch its outputs.
# usage: run_turn.sh N LABEL LOCAL_OUT
set -euo pipefail
N=$1 LABEL=$2 OUT=$3
R=personal-agent-turns-20261025 APP=personal-agent-turns-20261025
ssh zed-mesh "cat /data/amiller/$R/keeper-state/compose-turn-$N.json" | ssh mini-mesh "cat > ~/$R/compose-$LABEL.json"
ssh mini-mesh "cd ~/$R && open -n -W --stderr \$PWD/runner-$LABEL.log ~/vz-runner/runner/build/Runner.app --args run \
  --compose \$PWD/compose-$LABEL.json --app $APP --out \$PWD/out-$LABEL --base \$PWD/base \
  --kms http://127.0.0.1:19471 --oci-archive \$PWD/turn.oci.tar --attest; tail -5 runner-$LABEL.log"
mkdir -p "$OUT"
ssh mini-mesh "cd ~/$R && tar cf - runner-$LABEL.log compose-$LABEL.json out-$LABEL" | tar xf - -C "$OUT"
