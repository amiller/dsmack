# Personal agent turns

A personal agent's state carried across VM runs. Each turn is one `hvf-v3` boot of the
runner on the Mac. The turn decrypts the agent's state, increments a counter, encrypts
the new state for the next turn and signs the transition for the on-chain head.

The agent is one [secret-release](../../../dstack-compat/README.md) task: the turn's
compose manifest is the same for every turn, and the policy gives the task's secret only
to a guest that attests that manifest and image from the approved runner build. From the
secret the guest derives the state key for each turn (`agent-state/<turn>`) and a
secp256k1 key whose address is the agent.

The head is in [TurnHeads](../../../contracts/src/TurnHeads.sol): `heads(agent)` is
`(turn, state)`, the sha256 of the current state blob. A turn signs `(turn, state_in,
state_out)` and the commit moves the head only from `(turn, state_in)`, so a second turn
from the same parent, or one started from an older state, cannot land. The head and the
blobs come from the laptop, which is not trusted: a wrong head or blob makes the turn fail
its own check or the commit revert.

Files:
- `guest/agent_turn.py`, `guest/Dockerfile`: the turn (alpine, python3, cryptography, `dsmack_dstack.py`).
- `workload.py`: the compose manifest and the workload disk.
- `run_turn.py`: one turn from the laptop: reads the head, boots the turn on the Mac, sends the commit.

## Run

Deploy TurnHeads once (`forge create --root contracts src/TurnHeads.sol:TurnHeads`).
Build the turn image as an OCI layout and the workload, with the policy and state servers
at the Mac's loopback as the guest sees it through gvproxy:

```sh
SOURCE_DATE_EPOCH=0 docker buildx build --builder <oci builder> --platform linux/arm64 --provenance=false --sbom=false \
  --output type=oci,dest=turn.oci.tar,rewrite-timestamp=true -f applications/agent-turns/personal-agent/guest/Dockerfile .
mkdir -p image/oci-layout && tar -xf turn.oci.tar -C image/oci-layout
python3 applications/agent-turns/personal-agent/workload.py . <base image files> <canary-v1.app-compose.json> image \
  personal-agent/<name> http://192.168.127.254:8787 http://192.168.127.254:8788 <TurnHeads> <chain id> wl
```

`<base image files>` is a derived image whose supervisor starts the guest agent with
`--secret-key`. Provision the task once on Lit with a fresh secret that is not kept, and
record the agent's address:

```sh
deno run -A dstack-compat/secret-release/lit.mjs exec policy.json <(echo '{"op":"publicKey"}')   # -> pub
S=$(openssl rand -hex 32); mkdir agent
echo $S | PYTHONPATH=dstack-compat python3 applications/agent-turns/personal-agent/guest/agent_turn.py address > agent/agent
echo $S | deno run -A dstack-compat/secret-release/lit.mjs wrap <pub> personal-agent/<name> <manifest_sha256> <os_image_hash>
unset S
```

`tasks.json` is `{"personal-agent/<name>": {"manifest", "images": [<os_image_hash>], "wrapped"}}`.
On the laptop, with `LIT_STATE` the directory `lit.mjs setup` wrote, serve the policy
forwarder and the agent directory, and forward both to the Mac:

```sh
deno run -A dstack-compat/secret-release/lit.mjs serve policy.json tasks.json 127.0.0.1 8787
python3 -m http.server -d agent -b 127.0.0.1 8788
ssh -O forward -R 127.0.0.1:8787:127.0.0.1:8787 -R 127.0.0.1:8788:127.0.0.1:8788 $DSMACK_MAC_HOST
```

`~/$DSMACK_MAC_RUNNER` on the Mac holds `DsmackRunner.app`, `base/` (the image files) and
`enrollment/keyId.txt`. With `HEADS`, `ETH_RPC_URL` and a cast wallet (`ETH_KEYSTORE`) set:

```sh
python3 applications/agent-turns/personal-agent/run_turn.py wl agent   # turn 0 -> head (1, s1)
python3 applications/agent-turns/personal-agent/run_turn.py wl agent   # turn 1 -> head (2, s2)
```

```sh
python3 -m pytest -q applications/agent-turns/test_personal_agent.py
forge test --root contracts --match-contract TurnHeads
```
