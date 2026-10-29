# Compute node

A v0.2 guest daemon accepts one coding job at a time through a libp2p circuit
relay. It generates its identity, P-256 bundle key and Ed25519 receipt key at
boot, binds them with App Attest, and renews its broker registration every
25 seconds. Jobs and results use the [job protocol](PROTOCOL.md).

The image pins Claude Code 2.1.187. The measured compose sets `MODEL`
to `claude-opus-4-8`. `worker.py` calls
`agent-turns/find.py` for one edit turn. `/run/dsmack` points to the container's
`/dev/shm` tmpfs; the worker checks the mount before opening a credential. The
worker reads `/run/dsmack/credential` with mode `0400`. Inference-only tokens
go to the CLI through `CLAUDE_CODE_OAUTH_TOKEN`; refreshable documents use the
credential sentinel. The credential and temporary work tree are removed after
the job. Outputs travel over pipes and
are sealed before leaving the daemon. Result artifacts contain public registration, the
last sealed result, and network probe outcomes.

## Build on a Linux builder

From the repository root, with the qualified Claude image available locally:

```sh
(cd applications/compute-node/peer && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dsmack-compute .)
docker build -f applications/compute-node/Dockerfile \
  --build-arg QUALIFIED_CLAUDE_REPOSITORY=QUALIFIED_LOCAL_REPOSITORY \
  -t compute-node .
```

Export that image as a gzip OCI layout. Pack it with a starter compose manifest
whose `base_vm` describes the installed base image:

```sh
python3 applications/compute-node/workload.py REPO BASE STARTER OCI_DIR \
  sha256:IMAGE_DIGEST applications/compute-node/dsmack-compute \
  /ip4/RELAY_IP/tcp/RELAY_PORT/p2p/RELAY_ID \
  http://BROKER_IP:BROKER_PORT BROKER_ED25519_HEX RUNNER_CDHASH http://PROXY_IP:PROXY_PORT OUT 1800
```

The packer resolves the broker hostname once and measures its fixed `BROKER_IP`.
The node dials that IP while preserving the HTTPS hostname for certificate
verification. The guest allowlist contains exactly that endpoint, the circuit relay,
and the supplied proxy IP and port. Run the CONNECT proxy on that host with
`python3 applications/compute-node/connect-proxy.py --listen PROXY_IP --port PROXY_PORT`. It permits
only `CONNECT api.anthropic.com:443`; the CLI or sentinel verifies provider TLS
in its guest process. Its measured `HTTPS_PROXY` config selects the tunnel.

Admit the resulting compose/image/CDHash tuple at the broker, then launch the
workload using the installed v0.2 runner and the public `workload.img`, with no
private input disk. `GET /nodes` discovers live compute nodes. The daemon's
`serve` arguments are `RELAY SECONDS BROKER_URL BROKER_KEY CDHASH WORKER`.

## Transport helper

The same Go binary builds for a client host. `keygen FILE` creates its libp2p
key, `id FILE` prints the PeerId, and `sign FILE` signs a canonical JSON object
read on stdin. `exchange CIRCUIT KEY` relays framed stdin/stdout over
`/dsmack/job/1`. The client must verify discovery before using `exchange` and
wait for `ready` before sending its encrypted bundle.

## Test

```sh
(cd applications/compute-node/peer && go test -race ./...)
python3 -m unittest discover -s applications/compute-node -p 'test_*.py'
node --test applications/relay-broker/broker.test.mjs
```

## Run a remote turn

Build the transport helper for the client machine on the Linux builder, then
run from the source checkout:

```sh
applications/agent-turns/skill/dsmack-agent run-remote \
  --repo ./my-checkout --prompt 'Fix add so it adds its arguments.' \
  --out ./remote-turn --binary ./dsmack-compute --client-key ./client.key \
  --manifest ./compose-manifest.json --enrollment ./enrollment \
  --cdhash APPROVED_RUNNER_CDHASH --broker-key PINNED_BROKER_ED25519_HEX
```

The client discovers a registered node at the live broker, checks its Apple
assertion and the current CDRegistry and canary state through read-only RPC,
checks the exact compose and image, and fetches the registration directly over
the authenticated relay stream. The measured compose binds the broker key.
A signed seconds grant and the node's admission precede the credential read.
The client prefers `~/.dsmack/private-inputs/claude-oauth-token` from
`claude setup-token` when present, otherwise `claude-subscription.json`.
Use `--credential PATH` to select a source explicitly. It is projected and
sealed in memory alongside the repo snapshot and prompt. Inference-only
tokens use the CLI's native OAuth requests through the CONNECT proxy, with
no refresh or local expiry. The sentinel refreshes refreshable documents.

The client verifies the per-job assertion, receipt, sealed output digests and
observed model/tool use, then applies the patch with `git apply`. `--out` receives
the encrypted input and result, the verified plaintext patch, transcript and
verdict, and `turn.json`. The client uses broker HTTP, chain RPC and the relay;
it runs no remote shell command.

## Success-condition harness

Run the client probes on the credential owner's Mac. Keep its user-side
`client/` directory separate from the node's attempt directory and the builder's
operator directory. A JSON config supplies `binary`, `client_key`, `manifest`,
`enrollment`, `broker_key`, and `cdhash` using local paths; `broker`, `rpc`,
`attest`, `canary`, `credential`, `seconds`, and `marker_file` are optional.
`marker_file` names a shared JSON object mapping `credential`, `repo`, and
`prompt` to three random 32-byte hex values. Without it, `primary` generates
fresh markers. It keeps the provider tokens unchanged and marks accepted
credential metadata in memory.

```sh
python3 applications/compute-node/success_harness.py primary --config client.json --out client/primary
python3 applications/compute-node/success_harness.py expire --config client.json --capture client/primary --out expired.json
```

`primary` runs a real marked turn, verifies its attestation, receipt and model,
applies and checks the toy patch, then probes repeated jobs, a wrong client and
an exhausted grant. `expire` waits for that real signed grant to expire. After
the owner stops the node and boots the same compose again, test the captured
bundle under the new boot key:

```sh
python3 applications/compute-node/success_harness.py second-run --config client.json --capture client/primary --out replay.json
```

After the VM and network helper stop, scan every node-attempt and operator file.
Run the same scan with `--control` against a marked current `run-v02` attempt;
the control requires a hit for each marker.

```sh
python3 applications/compute-node/success_harness.py scan --root node-attempt --root operator-attempt --out scan.json < client/primary/markers.json
```

Let the node finish its measured running period so the guest exports its result
artifacts. After the VM and helper exit, preserve the original signed result
disk, then change one ciphertext byte in its exported `last-result` artifact.
Fetch both encrypted result versions to the user client and verify that only
the original is accepted:

```sh
python3 applications/compute-node/success_harness.py flip-output --disk result.img --artifact /compute-node-v1/outputs/artifacts/last-result --out tamper --stopped
python3 applications/compute-node/success_harness.py verify-tamper --config client.json --capture client/primary --original tamper/original.json --tampered tamper/tampered.json --out tamper-check.json
```

On macOS, pass `--debugfs /opt/homebrew/opt/e2fsprogs/sbin/debugfs` to `flip-output`.

`policy-refusal` checks an actual variant registration against the original
client config. `egress --proxy http://PROXY_IP:PROXY_PORT` joins the guest's network probe artifact
with a verified model turn. `assemble` writes `check.json` from an object with success-condition
keys `"1"` through `"7"` and each condition's evidence.

## Browser model jobs

`worker.py` accepts a delegated inference credential inside the sealed input:
`{"schema":"dsmack-delegated-inference/1","api_key":"…"}`. Pin the provider in
`workload.py`'s optional provider JSON:
`{"schema":"dsmack-tee-model/1","base_url":"https://MODEL_HOST/v1","model":"MODEL_ID"}`.
The agent uses OpenAI file tools to edit the repository. The guest-local egress
gateway admits only `POST /v1/chat/completions` to that hostname. Its HTTPS
connection crosses the measured CONNECT proxy, so the proxy receives ciphertext.
Gateway decisions are included in the sealed transcript as `gateway_event` lines.

Build the additional gateway executable on a Linux builder before building the
compute image:

```sh
(cd applications/egress-policy && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o ../compute-node/dsmack-egress .)
```

Run the transport proxy on its measured operator endpoint:

```sh
python3 applications/compute-node/connect-proxy.py --listen GATEWAY_IP \
  --port 18443 --model-host MODEL_HOST
```

Without a provider JSON, jobs use the pinned Claude CLI and the existing
`claudeAiOauth` credential format.

## Warm operator pool

Run the pool on the Mac. `RUNNER` holds the installed runner app, base image and
enrollment; `WORKLOAD` holds a packed `workload.img` and `compose-manifest.json`.
Pack it with an 840-second lifetime; its measured `ADMIT_SECONDS` is 570.

```sh
python3 applications/compute-node/pool.py --runner RUNNER --workload WORKLOAD \
  --state POOL_STATE --broker http://BROKER_IP:PORT --repo SOURCE_CHECKOUT
```

At 450 seconds, the daemon launches a replacement and waits for the broker's
verified attestation and binding before counting it as ready. Each old node
stops admitting jobs at 570 seconds, finishes admitted jobs and exits at 840
seconds, before the runner's 900-second watchdog. At most two owned VMs overlap.
The Mac preflight checks 12 GiB free and permits only runner sessions already
owned by this pool; another session's VM blocks a new launch.

`--cycles 2` runs two generations and exits. SIGINT/SIGTERM stops rotation and
waits for the owned VMs to finish. Each attempt preserves logs, launch assertions
and a verified gzip of the original result disk under `run-*/evidence/`. The
existing guarded cleanup checks open references before retiring that attempt's
scratch and staged disks, recording allocated bytes reclaimed and free space.
