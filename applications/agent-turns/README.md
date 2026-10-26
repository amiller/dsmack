# Agent turns

A turn is one VM run of a pinned agent:

```text
(agent, state_in, inputs, prompt) -> (state_out, outputs, transcripts, verdict)
```

A one-off finding is a turn with no state and a question with fixed answers. A
personal agent is a chain of turns: each starts from the state the previous one
wrote, and a dstack app keeps the head and releases the turn's state key only to
a run whose `state_in` is the head.

The turn has no evidence object of its own. The request is the run's one
committed input, the results are its declared outputs, and the execution receipt
already signs both.

## Request

File slot `turn`, delivered to the workload and committed by the receipt:

```json
{
  "schema": "dsmack-agent-turn/1",
  "agent": {
    "cli_version": "2.1.187",
    "cli_sha256": "b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2",
    "model": "claude-opus-4-8",
    "tools": ["Read", "Grep", "Glob"],
    "max_turns": 30,
    "wall_seconds": 900,
    "settings": {"disableAllHooks": true}
  },
  "prompt": "Can any workload container read the provider API key?",
  "answers": ["yes", "no", "unclear"],
  "runs": 3,
  "aggregate": "unanimous",
  "inputs_sha256": "<tree digest of the read-only inputs>",
  "state_in": null
}
```

`answers`, `runs` and `aggregate` are there when the turn asks a question. A
request without them is an edit turn: one run, tools from `Read, Grep, Glob,
Edit, Write`, on a git checkout of a copy of the inputs, and the staged diff is
the `patch` artifact.
`state_in` is the sha256 of the state ciphertext the turn starts from, or null.
The ciphertext itself arrives on the private input disk, which is not hashed, so
the workload checks it against `state_in` before decrypting. The check digest,
which names a reusable check for CI, is the request without `inputs_sha256` and
`state_in`.

## Outputs

Declared artifacts, flat names (the receipt allows 16 single-segment names):

| Artifact | Contents |
|---|---|
| `state` | new state ciphertext; absent for a stateless turn |
| `patch` | `git diff --binary` of an edit turn against the inputs |
| `verdict` | `{answer, aggregate, run_answers, observed_models}`; `answer` is null when the rule is not met |
| `verdict` (edit turn) | `{answer: null, summary, num_turns, observed_models}` |
| `run-N-transcript` | raw stream-json of run N |
| `run-N-verdict` | `{answer, rationale, citations, num_turns, observed_models}` |
| `run-N-stderr` | CLI stderr |
| `dashcam-head` | final hash of an interactive session's recording ([dashcam](dashcam/README.md)) |

## Where each field comes from in the compose receipt v4

| Turn field | Receipt field |
|---|---|
| agent image, network, credential profile, limits | `manifest_sha256`, `observed.services[].resolved_manifest_digest` |
| agent pin (CLI hash, model, tools, bounds) | request `agent`, inside `runtime_inputs_commitment.inputs_sha256` |
| prompt, answer type | request, same commitment |
| inputs | request `inputs_sha256`, same commitment; the tree is on the measured workload disk |
| state_in | request `state_in`, same commitment |
| state_out | `outputs.artifacts[name=state].sha256` |
| outputs | `outputs.artifacts` |
| transcript digests | `outputs.artifacts[name=run-N-transcript].sha256` |
| verdict | contents of the `verdict` artifact |

The commitment is `dsmack.task-commitment/3` with scope
`{"include": ["files"], "file_slots": ["turn"]}`, so a verifier recomputes it from
the request bytes alone. What is new: the request schema, the artifact names, and
the rule that a chain's `state_in` equals the previous `state_out`.

The mac-compose runner ([personal-agent/](personal-agent/README.md)) has no receipt v4.
There `compose_hash` commits `STATE_IN` through the compose environment, and the
guest's `/attest` assertion signs `{state_in, state_out, turn}`. `turn.py` reads
both kinds into the same turn.

## Run

`find.py` runs a stateless turn as the workload of a credentialed compose
manifest; the per-run sentinel endpoint arrives in `DSMACK_SENTINEL_ENDPOINT`.

```sh
python3 find.py --spec turn.json --inputs /inputs --output /workspace/artifacts
```

`turn.py` reads turns and checks a chain. `from_receipt(receipt, request_bytes,
outputs_dir)` takes a receipt the [run-result verifier](../pilot-client/verifier/README.md)
has accepted; `from_mac_compose(evidence, compose_bytes, cdhash, blobs_dir)` checks
the App Attest evidence itself; `check_chain(turns, genesis)` returns the head.

The sentinel that terminates TLS to `https://api.anthropic.com` inside the guest
is in [`base-vm/browser-sandbox-v1/source/guest/sentinel/`](../../base-vm/browser-sandbox-v1/source/guest/sentinel/),
copied byte for byte from `/usr/local/lib/dsmack/sentinel` in the
0.7.1.broker-timeout-v1 rootfs (`dstack.rootfs_hash=c62f6746…`).

## Dispatch to the Mac

`skill/dsmack-agent run` snapshots a local working tree and runs an edit turn in
the attested guest on a Mac; [`skill/SKILL.md`](skill/SKILL.md) tells a
local agent how to use it. The run follows [docs/running.md](../../docs/running.md):

1. The operator host (`mac.py admit`) puts the request in file slot `turn` and a tar of the
   snapshot in slot `tree` (at most 16 MiB), builds the measured workload disk
   with the image and the commitment declaration, has the
   [coordinator](../coordinator/README.md) sign a workload admission for a fresh
   attempt (`POST /admit`), and writes a checker context and a replay challenge.
2. The Mac pipes its local Claude login through `export_subscription.py` into
   `stage_private.py`, then runs `alpha_coordinator.py` prepare, check-only and
   execute on the installed release (profile `agent-turns-edit-v1`).
3. The operator host (`mac.py verify`) runs the run-result verifier on the Mac's original
   evidence, and `turn.from_receipt` reads the verified receipt and artifacts.

The guest runs `find.py` as the compose workload with `--inputs` pointing at
the tar; it checks the unpacked tree against the request's `inputs_sha256`.

One-time operator setup in `$DSMACK_OPERATOR_DIR` on the operator host, with
`source/` a copy of this checkout and `coordinator.env` exporting `DSMACK_COORDINATOR`
(the coordinator's URL), `DSMACK_OPERATOR_TOKEN` and the paths `mac.py` reads
(`DSMACK_BROKER_BUILD`, `DSMACK_OPERATOR_POLICY`).
`skill/dsmack-agent` reaches the two machines as `$DSMACK_OPERATOR_HOST` and `$DSMACK_MAC_HOST`. `release` has the coordinator
sign the inventory under its key id:

```sh
M="python3 -B source/applications/agent-turns/mac.py"
$M image --out image-1          # Dockerfile on the qualified 2.1.187 parent, as a gzip OCI layout
. ./coordinator.env
$M release --base-inventory BASE.json --base-archive BASE.tar.gz --oci image-1/oci-layout \
  --base BASE-IMAGE --sequence 30 --out release-1  # a prior release with this profile; current pilot-client
$M authorize --authority authority --registration DIR   # attestation.cbor, clientData.bin, keyId.txt of the Mac key
```

Then install `release-1` on the Mac with `alpha-bootstrap.mjs` and `alpha_stage.py`
into `~/dsmack-mac-dispatch-20261025/installed`, as in docs/running.md, with the
coordinator's `public_pem` from `GET /keys` as the bootstrap trust key.
`--base` is the guest image the release ships in `base/`. The alpha app (CDHash
`6b9baf8b…`) predates the guest Attest agent and does not answer on `dsmack-ctl`,
so it boots the B44 base (`os_image_hash` `b44abf14…`); a derived image
(`image.sha256`) stops with supervisor code 33 when the agent cannot seal.

### On the v0.2.0-canary.1 runner

`skill/dsmack-agent run-v02` runs the same turn on the v0.2.0-canary.1 runner
(CDHash `7011178c…`) and the derived image `image.sha256` (`c6bc2b7f…`), without the
alpha installer. `mac.py admit-v02` takes the alpha manifest, swaps in the `base_vm`
of `--base`, binds `/var/run/dstack.sock` and adds `find.py --attest`. After the
turn, `find.py` calls `/v1/Attest` with `report_data` = `find.report`: the
sha256 of `{request, patch, transcripts, verdict, dashcam, state_out}`, and
writes the attestation as the `attestation` artifact. The Mac stages the
credential as above and launches `DsmackRunner.app hvf-v3` with that private
disk. `turn.from_guest_attest` checks the runner key's App Attest attestation,
the Attest assertion over the rebuilt client data, the replayed event log
ending in `system-ready`, that `run` is the launch assertion's client data, the
compose (the manifest `admit-v02` admitted) and image hashes, and `report_data` against the artifacts.

Setup: `image-4` built by `mac.py image` and `base/` (the `derive.py` artifacts) in `$DSMACK_OPERATOR_V02_DIR` on the operator host,
and `~/dsmack-agent-turns-v02-20261025` on the Mac with the files the `V02_` comment in `skill/dsmack-agent` lists.

For private inputs, `compose-private.yml` runs the sentinel as a container on two
networks and the agent on an internal one only. `gateway_mode_ipv4: isolated`
(Docker 28) removes the bridge gateway, so the agent cannot reach the host either;
with `internal: true` alone the host's listeners stay reachable.

```sh
python3 -m pytest -q applications/agent-turns
```
