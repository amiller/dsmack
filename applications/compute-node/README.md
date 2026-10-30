# Compute node

The compute guest exposes Pi's `bash`, `read`, `write` and `edit` tools over an
attested libp2p stream. The agent loop and encrypted model calls run in the
browser. A conversation claims one guest on its first tool call, holds its
workspace, and releases it after five idle minutes or when the user ends it.
Guest seconds are charged from the conversation's chat credit.

The guest uses `@earendil-works/pi-coding-agent` **1.4.0**. Its actual tool
factories supply the schemas, descriptions, truncation, and edit behavior.
The official TypeScript MCP SDK uses its current split packages
`@modelcontextprotocol/server` and `@modelcontextprotocol/client` **2.4.0**,
which implement MCP **2026-07-28**.

## Transport and workspace

`/dsmack/agent-mcp/1.0.0` authenticates the existing broker-signed admission
against the libp2p Noise peer. After the ready frame, the stream carries only
newline-delimited UTF-8 JSON-RPC, using MCP's stdio framing. The official SDK
handles discovery, per-request metadata, cancellation, and progress. Bash output
arrives as `notifications/progress` while the command runs.

The Go daemon forwards the stream to the Node server's Unix socket at
`/run/dsmack/agent-mcp.sock`. Standard MCP resources provide
`dsmack://environment` and `dsmack://workspace/patch`. The latter returns the
workspace's binary Git diff as a base64 blob. Repository import uses the same
write and bash tools, then commits the imported baseline.

Tools run as `agent`, uid 1000 without supplementary groups. File operations
reject absolute paths and symlinks outside `/workspace`. The container root
filesystem is read-only; the writable workspace is tmpfs and lasts for the
conversation. Root-owned daemon state and the attestation socket are inaccessible
to the tool user. Shell commands can read installed system runtimes.

A command has a maximum 120-second timeout. Pi truncates model-facing text to
2000 lines or 50 KiB; commands producing more than 1 MiB of raw output stop.
The measured compose records those caps, the tool versions, and network policy.
The guest firewall permits the operator CONNECT proxy; that proxy enforces its
host allowlist. The browser verifies the measured compose, image and App Attest
binding before sending a tool request.

## Build on zed

From the repository root:

```sh
(cd applications/compute-node/peer && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dsmack-compute .)
(cd applications/egress-policy && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../compute-node/dsmack-egress .)
docker build -f applications/compute-node/Dockerfile -t compute-node .
```

Update an installed base with the measured agent runtime profile:

```sh
python3 base-vm/browser-sandbox-v1/update-runtime.py --base BASE --out BASE_UPDATE
```

Use `BASE_UPDATE/build/legs/diagnostic/files` as the new base. Export the tool
image as a gzip OCI layout and pack it with a starter compose manifest:

```sh
python3 applications/compute-node/workload.py REPO BASE STARTER OCI_DIR \
  sha256:IMAGE_DIGEST applications/compute-node/dsmack-compute \
  /ip4/RELAY_IP/tcp/RELAY_PORT/p2p/RELAY_ID \
  https://BROKER/relay-broker BROKER_ED25519_HEX RUNNER_CDHASH \
  http://PROXY_IP:PROXY_PORT OUT 840
```

For the Mac pool, the relay is
`/ip4/127.0.0.1/tcp/18082/ws/p2p/MAC_RELAY_PEER`, the proxy is
`http://192.168.127.254:18484`, and the tunnel index is a same-host HTTPS URL
such as `https://pod.dstack.soc1024.com/private-agent/tunnels`.
The guest's hostname gateway verifies broker TLS and the discovered quick-tunnel
hostname. Noise authenticates the relay PeerId measured in the compose.

## Test

```sh
(cd applications/compute-node && npm ci --ignore-scripts && npm test)
(cd applications/compute-node/peer && go test -race ./...)
python3 -m unittest discover -s applications/compute-node -p 'test_*.py'
```

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
The relay allows eight reservations and four circuits per peer, with a 35-minute,
128-MiB-per-direction circuit budget; a verified model transcript is about
3 MB after encryption/hex framing. The guest WebSocket gateway retains a
32-MiB cumulative budget per direction and refunds unused reservations.

Lease renewal logs its stage, HTTP status and bounded response body. Transient
HTTP/network failures retry on the next 25-second tick, up to three consecutive
failures; attestation refusals stop the node. Admitted calls are never resubmitted.

Tunnel-index publication records every failing HTTP status and bounded response
body, then retries transient errors up to three times, five seconds apart. These
retries only repeat the HTTP publication; a completed chain write is never sent
again.

The launcher queries public A records with `dig` and gives the CONNECT helper
per-process bindings, retaining hostname TLS verification. This avoids stale
Mac resolver cache entries without changing resolver settings. The relay permits
90 seconds of WAN write backpressure while keeping its circuit caps.
