---
name: dsmack-dispatch
description: Hand a bounded coding task on a local git checkout to the pinned dsmack agent, which edits a snapshot in the attested guest on the Mac mini and returns a patch, its transcript and a turn record. Use when the user asks to dispatch, delegate or send a task to a remote worker or the pinned agent, or wants a change made by the pinned agent rather than by you.
---

# Dispatch a task to the pinned agent

The pinned agent is Claude Code 2.1.187 with model `claude-opus-4-8`, run by
`find.py` in the `agent-turns` image. It sees only a snapshot of the working
tree (tracked and untracked, not ignored files; at most 16 MiB), has the tools
you allow and no shell, and cannot commit. Its only network peer is the
sentinel, which adds the provider key.

## When

Dispatch a task that one agent can finish from the files alone in about eight
minutes and 30 turns: a fix, a small feature, a refactor, a test. Do not
dispatch work that needs to run code, reach the network or read files outside
the repository. Write a self-contained prompt; the agent sees nothing of this
conversation.

## Run

```sh
DSMACK_AGENT=<dsmack checkout>/applications/agent-turns/skill/dsmack-agent
"$DSMACK_AGENT" run --repo "$REPO" --prompt "$PROMPT" \
  --out "$SCRATCH/dispatch-$(date +%s)"
```

- The agent uses the Claude login on the Mac
  (`~/.dsmack/private-inputs/claude-subscription.json` there). If staging
  refuses it as expired, ask the user to log in on the Mac; never copy a
  credential between machines yourself.
- `run-v02` takes the same arguments and runs on the v0.2.0-canary.1 runner and
  base image. `--out` then also holds `artifacts/attestation` (the guest Attest
  over the request, patch, transcript and verdict), `out/` (the runner's launch
  evidence), `result/` and `turn.json` with the checked `attest` fields. A
  run takes about three minutes.
- `--tools` defaults to `Read,Grep,Glob,Edit,Write`; pass `Read,Grep,Glob` for a
  read-only task.
- `--wall-seconds` (480) and `--max-turns` (30) match the Mac develop recipe.
- `--out` must not exist and must be outside `--repo`.

It prints the path of the patch on success. `--out` then holds `request.json`,
`inputs/` (the snapshot), `admission.json`, `verification.json`, the verified
`receipt.json` and signed `report.json`, `turn.json` (the turn record from
`turn.py`) and `artifacts/` (`patch`, `run-1-transcript`, `run-1-stderr`). A
run takes about ten minutes. A failed run exits non-zero with the reason; the
out path is printed first.

## Review and apply

1. Read the patch in full. Check it does what the prompt asked and nothing
   else: no edits to CI, build scripts, credentials or files the task did not
   need.
2. Skim the last events of `run-1-transcript` for the agent's summary.
3. The CLI already ran `git apply --check` against the working tree. Apply with
   `git -C "$REPO" apply "$PATCH"`, then run the repository's tests.
4. Show the user the diff stat and your review before committing anything.

If the working tree changed since the dispatch, `git apply --3way` may still
apply it; otherwise re-dispatch.
