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
  /ip4/127.0.0.1/tcp/18082/ws/p2p/MAC_RELAY_PEER \
  https://pod.dstack.soc1024.com/relay-broker BROKER_ED25519_HEX RUNNER_CDHASH \
  http://192.168.127.254:18484 OUT 840 PAYMENTS_JSON_OR_- \
  https://pod.dstack.soc1024.com/private-agent/tunnels [OPERATOR_JSON]
```

The tunnel index must be on the broker's host. The guest's hostname gateway verifies broker TLS and the discovered quick-tunnel
hostname. Noise authenticates the relay PeerId measured in the compose.

## Test

```sh
(cd applications/compute-node && npm ci --ignore-scripts && npm test)
(cd applications/compute-node/peer && go test -race ./...)
python3 -m unittest discover -s applications/compute-node -p 'test_*.py'
```

## Mac pool

Write `~/.dsmack/operator.json` on the Mac:

```json
{"max_guests":4,"guest":{"mem_mib":4096,"vcpus":1},"reserve":{"mem_gb":16,"cores":4}}
```

The pool checks physical RAM and cores at startup and refuses a configuration
whose guests exceed the capacity after the reserve, reporting the requested,
physical, reserved and available numbers. Editing the file takes effect on
restart; `--operator PATH` selects another configuration.

Pack the matching guest size by supplying the operator file as the final
argument to `workload.py`. The compose manifest and launch
image's `resource_profiles` bind the memory and vCPU count. Each size uses its
own escrow node class, compose measurement and price; register the packed class
with `applications/payments/register-class.mjs` before starting the pool.

Each configured slot rotates independently: a replacement starts after 450
seconds, the old guest stops admitting at 570 seconds and exits at 840 seconds.
Up to two generations per slot overlap during handover. Boot registration is
serialized to associate each guest's broker identity with its owned VM. A failed
guest is preserved, retired and replaced. Three consecutive failures stop only
that slot; successful retirement resets its failure count. Other slots continue.
The preflight requires 12 GiB free and waits while another lane owns a VM.

The Mac posts signed fleet heartbeats every 15 seconds with the operator config,
hardware, active and draining guests, errors and source commit. The publisher
uses the existing Mac tunnel-discovery key. Link that publisher to an operator
with `dsmack link` before starting the pool. Heartbeats contain no payout or
operator assertion; the broker takes the operator from the signed ownership link.
The broker's `/fleet?operator=ADDRESS` endpoint serves
the latest status; the fleet page reads job and earnings events from the escrow.

`mac-pool.py` starts the loopback libp2p relay, its broker backhaul, a Cloudflare
quick tunnel, the allowlisted CONNECT proxy, and the guest pool. It publishes
signed, expiring relay hints to the HTTP index and Base Sepolia.

```sh
VENV/bin/python applications/compute-node/mac-pool.py \
  --runner RUNNER --workload WORKLOAD --state SHORT_FRESH_STATE \
  --relay MAC_RELAY_BINARY --relay-key MAC_RELAY_KEY \
  --cloudflared CLOUDFLARED --publisher-key MAC_PUBLISHER_KEY \
  --publisher-address PUBLISHER_ADDRESS --registry TUNNEL_REGISTRY \
  --pool-version SOURCE_COMMIT \
  --broker https://pod.dstack.soc1024.com/relay-broker \
  --index https://pod.dstack.soc1024.com/private-agent/tunnels
```

Stop with `kill -TERM LAUNCHER_PID`. It drains owned guests, preserves logs,
assertions, original result disks and signed receipts, retires temporary disks,
clears its discovery hints, and stops its relay, tunnel and helper. Each
`run-*/evidence/` directory retains the guest evidence and reclaimed-space record.
No launchd or systemd service is installed.

### Encrypted workspace store

Run the loopback store with the existing Kubo API and an eth-account environment:

```sh
python3 workspace-store.py --state /path/to/workspace-store \
  --publisher MAC_PUBLISHER_ADDRESS --broker-signer BROKER_PAYMENT_ADDRESS
cloudflared tunnel --no-autoupdate --url http://127.0.0.1:15093
```

Configure the resulting HTTPS URL under the broker's `workspaces.stores` entry
for this publisher. The store accepts only broker-signed ciphertext operations,
spools chunks to disk, checks the ciphertext hash, and pins the encrypted archive
on IPFS. Reads use the local cache or fetch and verify the CID through Kubo.
Unused snapshots and incomplete uploads expire after 30 days. Retention removes
only this store's files and recursive pins it created.
