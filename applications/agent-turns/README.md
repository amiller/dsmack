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

Build the agent image on Zed from the qualified Claude Code 2.1.187 image:

```sh
DOCKER_BUILDKIT=0 docker build --build-arg QUALIFIED_CLAUDE_REPOSITORY=<local name> -t agent-turns .
```

`skill/dsmack-agent run` snapshots a local working tree, runs an edit turn
through `compose-private.yml` in Docker on zed and checks what comes back with
`from_receipt`; [`skill/SKILL.md`](skill/SKILL.md) tells a local agent how to
use it. Zed returns an unsigned receipt built from the artifact digests it
reports. `DSMACK_DISPATCH_CREDENTIAL=<key file on zed> python3 -m pytest
test_dispatch.py` runs it end to end with the fake CLI.

For private inputs, `compose-private.yml` runs the sentinel as a container on two
networks and the agent on an internal one only. `gateway_mode_ipv4: isolated`
(Docker 28) removes the bridge gateway, so the agent cannot reach the host either;
with `internal: true` alone the host's listeners stay reachable.

```sh
python3 -m pytest -q applications/agent-turns
```
