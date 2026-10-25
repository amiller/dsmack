# Agent turns with a head-keeping KMS

A personal agent's state carried across VM runs. Each turn is one boot of the
mac-compose runner (`private-code/runner/`, the build installed on the mini at
`~/vz-runner/runner/build/Runner.app`), not the V3 runner. The turn decrypts the
agent's state, increments a counter, encrypts the new state for the next turn,
and has the runner assert `{state_in, state_out, turn}` with App Attest.

`keeper.py` stands in for the dstack server. It speaks the runner's KMS protocol
and keeps the head: the hash of the current state blob. The turn's `STATE_IN` is
in the compose environment, so `compose_hash` commits to it. The keeper releases
`app_key` only to an attested boot of the runner's CDHash whose `compose_hash` is
the one for the current head. The guest gets its state keys from `/key`
(`agent-state/<turn>`), so a turn started from any older state never gets a key.
`POST /commit` checks the guest's `/attest` evidence and advances the head.

Files:
- `keeper.py`: head keeper (runs on zed, synthetic key only).
- `guest/turn.py`, `guest/Dockerfile`: the turn workload (alpine, python3, cryptography).
- `run_turn.sh`: boots one turn on the mini from the laptop and fetches its outputs.

## Run

On zed, from a copy of this repository under `/data`:

```sh
SOURCE_DATE_EPOCH=0 docker buildx build --builder abalone-oci --platform linux/arm64 \
  --provenance=false --sbom=false --output type=oci,dest=turn.oci.tar,rewrite-timestamp=true \
  experiments/personal-agent-turns/guest
python3 -I experiments/personal-agent-turns/keeper.py --state keeper-state --genesis \
  --cdhash "$(ssh mini-mesh cat vz-runner/runner/build/cdhash.txt)" --app personal-agent-turns-20261025 \
  --image docker.io/dsmack/personal-agent-turn@sha256:<manifest digest> --port 19471
```

From the laptop, forward the keeper to the mini's loopback through the existing
control masters:

```sh
ssh -O forward -L 127.0.0.1:19471:127.0.0.1:19471 zed-mesh
ssh -O forward -R 127.0.0.1:19471:127.0.0.1:19471 mini-mesh
```

On the mini, make `~/personal-agent-turns-20261025/` holding `turn.oci.tar` and a `base/`
with `vmlinux-arm64` linked to `~/vz-runner/vmlinux-arm64` and `store/` cloned
(`cp -c`) from `~/vz-runner/store/{content,state.json}`. Then:

```sh
run_turn.sh 1 turn1 OUT     # head moves to turn 2
run_turn.sh 2 turn2 OUT     # head moves to turn 3
run_turn.sh 2 replay2 OUT   # refused: KMS /release -> 403 stale_head
```

Result on 25 October 2026: both turns committed, the keeper decrypted the final
state as `counter: 2`, the replayed boot got `403 stale_head: compose is not the
current head`, and re-posting turn 2's commit got `403 stale_head: evidence is
not for the current head`.
