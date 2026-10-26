# Dashcam

A recording of an interactive agent session that neither the user nor the agent can edit.
The user types into Claude Code from a local terminal; the agent runs in the guest. The user
gets a shell in the agent container, so the recorders run in other containers:

```text
laptop tmux ──ssh──> relay ──private net──> agent: ptyd -> tmux -> claude
                       │                                          │
                       │                       private net        v
                       │                                   sentinel ──TLS──> api.anthropic.com
                       v                                          │
                   chain.jsonl  <─────────────────────────────────┘
```

- `relay.py` joins the user's terminal to the agent's `ptyd.py` and appends every input and
  output chunk, each window size, and each attach and detach.
- `sentinel_rec.py` runs the guest sentinel unchanged and appends every request and response
  it handles, with the run token redacted from paths and credential headers dropped.
- `dashcam.py close` appends the agent CLI's own transcripts, closes the chain and writes its
  head to `dashcam-head`, a declared artifact. The receipt binds it like any other output, and
  `turn.py` reports it as the turn's `dashcam`.

Each line of `chain.jsonl` carries the hash of the line before it. Writers take an flock on the
shared file, so the relay and sentinel append to one sequence.

## Run

On a docker host, with a dummy credential file:

```sh
docker build -f Dockerfile.agent -t dashcam-agent:spike .
docker compose -p dashcam --env-file env -f compose.yml up -d
```

`env` sets `RECORDER_IMAGE` (any Python 3 image), `AGENT_IMAGE`, `RUN_ID`, `SENTINEL_TOKEN`,
`DASHCAM_SOURCE` (this directory), `SENTINEL_SOURCE`
(`base-vm/browser-sandbox-v1/source/guest/sentinel`), `CREDENTIAL_FILE`, `CHAIN` and `OUTPUT`.

From the laptop:

```sh
ssh -t <docker host> docker exec -it dashcam-relay-1 python3 relay.py
```

Detach and reattach freely; the tmux session lives in the agent container. To finish:

```sh
docker compose -p dashcam -f compose.yml stop sentinel agent
docker exec dashcam-relay-1 python3 dashcam.py close --chain /dashcam --transcripts /transcripts --output /out
python3 dashcam.py verify chain.jsonl dashcam-head
python3 dashcam.py cast chain.jsonl > session.cast && asciinema play session.cast
```

`latency.py N -- command` times keystroke echo through any terminal command.
