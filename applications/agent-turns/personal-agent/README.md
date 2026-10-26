# Agent turns with a head-keeping coordinator

A personal agent's state carried across VM runs. Each turn is one boot of the
mac-compose runner (installed on the Mac at `~/vz-runner/runner/build/Runner.app`),
not the V3 runner. The turn decrypts the
agent's state, increments a counter, encrypts the new state for the next turn,
and has the runner assert `{state_in, state_out, turn}` with App Attest.

The dstack app in [applications/coordinator](../../coordinator/README.md) keeps
the head: the hash of the current state blob. It speaks the runner's KMS
protocol under `/turn`. The turn's `STATE_IN` is in the compose environment, so
`compose_hash` commits to it. The coordinator releases the agent's `app_key`
only to an attested boot of a CDRegistry-admitted runner build whose
`compose_hash` is the one for the current head. The guest gets its state keys
from `/key` (`agent-state/<turn>`), so a turn started from any older state never
gets a key. `POST /turn/commit` checks the guest's `/attest` evidence and
advances the head.

Files:
- `guest/turn.py`, `guest/Dockerfile`: the turn workload (alpine, python3, cryptography).
- `run_turn.sh`: boots one turn on the Mac from the laptop and fetches its outputs.

## Run

On a docker host, from a copy of this repository, build the turn image:

```sh
SOURCE_DATE_EPOCH=0 docker buildx build --builder abalone-oci --platform linux/arm64 \
  --provenance=false --sbom=false --output type=oci,dest=turn.oci.tar,rewrite-timestamp=true \
  applications/agent-turns/personal-agent/guest
```

Run the coordinator (see its README) and create the agent with an operator call:
`POST /agent {"agent": "personal-agent-turns-20261025", "image":
"docker.io/dsmack/personal-agent-turn@sha256:<manifest digest>", "port": 19471,
"ciphertext": <genesis state blob, base64>}`.

From the laptop, forward the coordinator to the laptop's and the Mac's loopback
through the existing control masters:

```sh
ssh -O forward -L 127.0.0.1:19471:<coordinator host:port> <coordinator ssh host>
ssh -O forward -R 127.0.0.1:19471:127.0.0.1:19471 $DSMACK_MAC_HOST
```

On the Mac, make `~/personal-agent-turns-20261025/` holding `turn.oci.tar` and a `base/`
with `vmlinux-arm64` linked to `~/vz-runner/vmlinux-arm64` and `store/` cloned
(`cp -c`) from `~/vz-runner/store/{content,state.json}`. Then:

```sh
run_turn.sh turn1 OUT     # head moves to turn 2
run_turn.sh turn2 OUT     # head moves to turn 3
```

Booting the runner again with `compose-turn2.json` is refused:
`KMS /release -> 403 stale_head`.
