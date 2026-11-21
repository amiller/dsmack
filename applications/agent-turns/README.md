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

`find.py` runs a stateless turn as the `agent` service of the compose; the
sentinel endpoint, with its per-run token, arrives in `SENTINEL_ENDPOINT`.

```sh
python3 find.py --spec turn.json --inputs /inputs --output /workspace/artifacts
```

`turn.py` reads turns and checks a chain. `from_receipt(receipt, request_bytes,
outputs_dir)` takes a receipt the [run-result verifier](../pilot-client/verifier/README.md)
has accepted; `from_guest_attest` checks a turn's guest Attest (below);
`from_mac_compose(evidence, compose_bytes, cdhash, blobs_dir)` checks
the App Attest evidence itself; `check_chain(turns, genesis)` returns the head.

## Dispatch to the Mac

`skill/dsmack-agent run` snapshots a local working tree and runs an edit turn in
the attested guest on a Mac; [`skill/SKILL.md`](skill/SKILL.md) tells a
local agent how to use it. No operator host or coordinator takes part in a turn.

The compose (`manifest()` in `mac.py`) has two services on one image:

- `agent` runs `find.py --attest --from-env` on the request and snapshot, which
  arrive base64-encoded in the private env values `TURN` and `TREE_0`..`TREE_7`
  (the gzipped tar in chunks under Linux's 128 KiB limit per env string). It has no network: with `network.service_egress` it sits only on
  the guest's service bridge, where it reaches `sentinel`.
- `sentinel` runs `sentinel_env.py`, which hands the credential to
  [`sentinel.py`](../../base-vm/browser-sandbox-v1/source/guest/sentinel/) on a pipe
  in `claude-subscription` mode. It alone may reach api.anthropic.com
  (160.79.104.0/23:443) and the resolver. The credential is a Claude setup token
  (`claude setup-token`, one year, inference only), which the sentinel sends as a
  Bearer token and never refreshes.

This is #103's route: the credential proxy is part of the application's measured
compose, so the base image carries no provider code and needs no change for it.

Per turn, the laptop sends the Mac `request.json`, `tree.tar` and three helpers
from this checkout. The Mac pipes `~/.dsmack/private-inputs/claude-oauth-token`
through `export_subscription.py` into `private_inputs.py`, which writes the
private input disk: one runtime-input envelope with `TURN`, `TREE_*` and the
sentinel endpoint (agent only), and the credential and a fresh sentinel token
(sentinel only). They are env values rather than file slots because the
8783a3be runner fails any manifest with file slots (`KeyError: 'slot'` in
`lifecycle.parser_validate`); env values are capped at 1 MiB in total, so the
gzipped snapshot must stay under about 700 KiB. It then boots the fixed workload disk once with `DsmackRunner.app
hvf-v3`. `turn.from_guest_attest` checks the runner key's App Attest attestation,
the Attest assertion over the rebuilt client data, the replayed event log ending
in `system-ready`, that `run` is the launch assertion's client data, the compose
(`MANIFEST`) and image (`OS_IMAGE`) hashes, that the caller is the `agent`
service, and `report_data` against the artifacts. The private disk is not
measured; `report_data` binds the request and the results, and `find.py`
checks the snapshot against the request's `inputs_sha256`.

Pins in `skill/dsmack-agent`: runner `CDHASH` `0c3d3c90…` (the Layover hosts'
DsmackRunner, enrolled on the mini), base `OS_IMAGE` `8783a3be…` (the Layover
guests' base), `MANIFEST` and `WORKLOAD` from `mac.py workload` of image
`sha256:d4fcf41e…`.

### Build (once per image, on the operator host)

On zed as `devops`, in `/data/devops/dsmack-agent-turns`: `qualified-claude-2.1.187/`
is the OCI layout of the qualified parent, `base-8783a3be/` the base bundle,
`source/` a `git archive` of this checkout, and `agent-turns` a docker-container
buildx builder.

```sh
M="python3 -B source/applications/agent-turns/mac.py"
$M image --builder agent-turns --qualified qualified-claude-2.1.187 --out image-1   # prints the image digest
$M workload --image image-1 --base base-8783a3be --out workload-1                   # prints manifest and workload sha256
```

Put the printed digests in `skill/dsmack-agent`, then install on the Mac in
`~/dsmack-agent-turns-20261121`:

- `runner/DsmackRunner.app`: a link to the enrolled app with `CDHASH`;
  `runner/enrollment/`: its key's `attestation.cbor`, `clientData.bin`, `keyId.txt`;
  `runner/runtime/`: `base/{scratch,result}-template.ext4` and `helper/gvproxy-darwin`;
  `runner/base/`: the base bundle (`cp -c` clones).
- `workload/`: `workload.img` and `compose-manifest.json` from `workload-1`.

`skill/dsmack-agent doctor` checks all of this, the token file, the disk and
whether another turn is running, without launching. The Mac's compute pools pause
while a runner VM they cannot see runs, so the turn links its run dir into `~/ds`
and `~/dl` for its lifetime, as Layover's `run-mini.sh` does.

```sh
python3 -m pytest -q applications/agent-turns
```
