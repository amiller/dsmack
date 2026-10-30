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

From the repository root, with the Claude image available locally:

```sh
(cd applications/compute-node/peer && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dsmack-compute .)
(cd applications/egress-policy && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../compute-node/dsmack-egress .)
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
  http://BROKER_IP:BROKER_PORT BROKER_ED25519_HEX RUNNER_CDHASH http://PROXY_IP:PROXY_PORT OUT 840
```

For the Mac warm pool, use relay
`/ip4/127.0.0.1/tcp/18082/ws/p2p/MAC_RELAY_PEER`, proxy
`http://192.168.127.254:18484`, provider JSON and the final `TUNNEL_INDEX`
argument `https://pod.dstack.soc1024.com/private-agent/tunnels`. The measured
firewall allows only that Mac proxy. A guest-local hostname gateway verifies
broker TLS; a second gateway verifies the discovered quick-tunnel hostname and
passes WebSocket upgrades. The tunnel index is an untrusted locator: its relay
PeerId must match the measured compose, and Noise authenticates the dial.

For a direct-IP operator route, the packer resolves and measures `BROKER_IP`
and allows the explicit broker, relay and proxy endpoints.

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
deno test --allow-read --allow-net applications/relay-broker/broker.test.mjs
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

## Browser model jobs

`worker.py` accepts a job-scoped broker capability inside the sealed input:
`{"schema":"dsmack-broker-inference/1","token":"…","job_id":"…"}`. Pin its
broker/model in the workload's provider JSON:
`{"schema":"dsmack-broker-model/1","base_url":"https://BROKER/relay-broker","model":"MODEL_ID","broker_key":"ED25519_HEX"}`.
The agent uses file tools to edit the repository. The guest-local egress gateway
permits only `POST /relay-broker/sandbox/inference` to that hostname and validates
TLS over the measured CONNECT proxy. The broker verifies NEAR gateway/per-model
attestation and encrypts the model request. It handles plaintext inside its CVM;
the NEAR API key never reaches the browser or compute node. Each completion is
signed by the pinned broker key and binds the job, fresh nonce, request hash,
model, attestation and result. Those records and gateway decisions are sealed in
the transcript. The capability permits eight requests and expires with its grant.

Run the transport proxy on its measured operator endpoint:

```sh
python3 applications/compute-node/connect-proxy.py --listen GATEWAY_IP \
  --port 18443 --model-host BROKER_HOST
```

Without provider JSON, jobs use the pinned Claude CLI and `claudeAiOauth` format.

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

`--cycles 2` runs two generations and exits. For a shorter rehearsal, pack a
420-second workload with `admit_seconds=330` and run with `--seconds 420
--drain-seconds 90 --replace-after 210 --readiness-timeout 90 --cycles 2`. SIGINT/SIGTERM stops rotation and
waits for the owned VMs to finish. Each attempt preserves logs, launch assertions
and a verified gzip of the original result disk under `run-*/evidence/`. The
existing guarded cleanup checks open references before retiring that attempt's
scratch and staged disks, recording retired allocated bytes and free space. A
guest failure is recorded after preserving and retiring its owned disks; the
pool stops rotation and returns a failure even if the host driver exited zero.

## Mac-owned tunnel lifetime

`mac-pool.py` starts the capped loopback WebSocket relay, its outbound broker
backhaul, a Cloudflare quick tunnel, a two-host opaque CONNECT helper and the
warm pool. It publishes the relay locator to the HTTP index and Base Sepolia
with a publisher key generated and retained on the Mac. Locator transactions
use one explicit public RPC (`--publication-rpc`, default PublicNode), verify
chain 84532 and retain the transaction fee, gas and balance caps. Their hints
remain untrusted; payment and attestation quorum verification is unchanged.
No RPC fallback or transaction resubmission is performed. The HTTP index saves
signed, expiring hints in its project data directory, preserving them across
page redeploys. No service is installed.

```sh
VENV/bin/python applications/compute-node/mac-pool.py \
  --runner RUNNER --workload WORKLOAD --state SHORT_FRESH_STATE \
  --relay MAC_RELAY_BINARY --relay-key MAC_RELAY_KEY \
  --cloudflared CLOUDFLARED --publisher-key MAC_PUBLISHER_KEY \
  --publisher-address PUBLISHER_ADDRESS --registry TUNNEL_REGISTRY \
  --broker https://pod.dstack.soc1024.com/relay-broker \
  --index https://pod.dstack.soc1024.com/private-agent/tunnels
```

Stop with `kill -TERM LAUNCHER_PID`. It stops rotation, drains guests, preserves
their evidence and retires their temporary disks, clears both discovery sources,
and stops its relay, tunnel and helper. Restart with a fresh short state path.
The relay allows eight reservations and four circuits per peer, with a two-minute,
8-MiB-per-direction circuit budget; a verified model transcript is about
3 MB after encryption/hex framing. The guest WebSocket gateway retains a
32-MiB cumulative budget per direction and refunds unused reservations.

Lease renewal logs its stage, HTTP status and bounded response body. Transient
HTTP/network failures retry on the next 25-second tick, up to three consecutive
failures; attestation refusals stop the node. Admitted jobs are never resubmitted.

The launcher queries public A records with `dig` and gives the CONNECT helper
per-process bindings, retaining hostname TLS verification. This avoids stale
Mac resolver cache entries without changing resolver settings. The relay permits
90 seconds of WAN write backpressure while keeping its circuit caps.
