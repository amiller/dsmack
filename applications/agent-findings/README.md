# Agent findings

`find.py` runs a pinned Claude Code agent over a read-only input tree, asks one
question with a fixed set of answers, and writes per-run `verdict.json` and
`transcript.jsonl` plus an aggregate `finding.json`. Run it as the workload of a
credentialed compose manifest; the per-run sentinel endpoint arrives in
`DSMACK_SENTINEL_ENDPOINT` and the execution receipt signs the output files.
The claim is "this pinned agent, on these inputs, answered X".

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

```sh
python3 find.py --spec spec.json --inputs /inputs --output /output
python3 -m unittest discover -s applications/agent-findings -v
```
