---
name: dsmack-dispatch
description: Hand a bounded coding task on a local git checkout to the pinned dsmack agent, which edits a snapshot in a container on zed and returns a patch, its transcript and a turn record. Use when the user asks to dispatch, delegate or send a task to a remote worker or the pinned agent, or wants a change made by the pinned agent rather than by you.
---

# Dispatch a task to the pinned agent

The pinned agent is Claude Code 2.1.187 with model `claude-opus-4-8`, run by
`find.py` in the `agent-turns` image. It sees only a snapshot of the working
tree (tracked and untracked, not ignored files; at most 32 MiB), has the tools
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
  --out "$SCRATCH/dispatch-$(date +%s)" --credential "$KEY_FILE_ON_ZED"
```

- `--credential` is the path of the provider key file on zed. Ask the user for
  it; never copy a key to zed or anywhere else yourself.
- `--tools` defaults to `Read,Grep,Glob,Edit,Write`; pass `Read,Grep,Glob` for a
  read-only task.
- `--wall-seconds` (480) and `--max-turns` (30) match the Mac develop recipe.
- `--out` must not exist and must be outside `--repo`.

It prints the path of the patch on success. `--out` then holds `request.json`,
`inputs/` (the snapshot), `receipt.json`, `turn.json` (the turn record from
`turn.py`), `compose.log` and `artifacts/` (`patch`, `run-1-transcript`,
`run-1-stderr`). A failed run exits non-zero with the reason; the artifacts
path is printed first, so read `run-1-transcript`, `run-1-stderr` and
`compose.log` there.

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
