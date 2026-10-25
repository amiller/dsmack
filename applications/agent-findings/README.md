# Agent findings

`find.py` runs a pinned Claude Code agent over a read-only input tree, asks one
question with a fixed set of answers, and writes per-run `verdict.json` and
`transcript.jsonl` plus an aggregate `finding.json`. Run it as the workload of a
credentialed compose manifest; the per-run sentinel endpoint arrives in
`DSMACK_SENTINEL_ENDPOINT` and the execution receipt signs the output files.
The claim is "this pinned agent, on these inputs, answered X".

The sentinel that terminates TLS to `https://api.anthropic.com` inside the guest
is in [`base-vm/browser-sandbox-v1/source/guest/sentinel/`](../../base-vm/browser-sandbox-v1/source/guest/sentinel/),
copied byte for byte from `/usr/local/lib/dsmack/sentinel` in the
0.7.1.broker-timeout-v1 rootfs (`dstack.rootfs_hash=c62f6746…`).

A check is the spec without `inputs_sha256`: agent pin, question, answers, run
count and aggregation. `check_sha256` names it, so the same check can be rerun
on new inputs (CI) or once (a one-off finding).

```json
{
  "schema": "dsmack-agent-check/1",
  "question": "Can a workload read the provider API key?",
  "answers": ["yes", "no", "unclear"],
  "runs": 3,
  "aggregate": "unanimous",
  "agent": {
    "cli_version": "2.1.187",
    "cli_sha256": "b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2",
    "model": "claude-opus-4-8",
    "tools": ["Read", "Grep", "Glob"],
    "max_turns": 30,
    "wall_seconds": 900,
    "settings": {"disableAllHooks": true}
  },
  "inputs_sha256": "<tree_digest of the inputs directory>"
}
```

Build the image on Zed from the qualified Claude Code 2.1.187 image:

```sh
DOCKER_BUILDKIT=0 docker build --build-arg QUALIFIED_CLAUDE_REPOSITORY=<local name> -t agent-findings .
```

For private inputs, `compose-private.yml` runs the sentinel as a container on two
networks and the agent on an internal one only. `gateway_mode_ipv4: isolated`
(Docker 28) removes the bridge gateway, so the agent cannot reach the host either;
with `internal: true` alone the host's listeners stay reachable.

```sh
python3 find.py --spec spec.json --inputs /inputs --output /output
python3 -m unittest discover -s applications/agent-findings -v
```
