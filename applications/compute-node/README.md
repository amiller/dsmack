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

See the [layered protocol](../../docs/protocol.md) for binding and wire contracts.

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
The guest firewall permits the operator CONNECT proxy. The proxy admits the
broker, the relay tunnel and the package hosts in `package-hosts.json` for every
guest. Anything else follows the stay's browse policy: the guest's tool server
forwards each CONNECT through a loopback forwarder that adds the stay's browse
token, and the proxy looks the token up at `BROKER/agent/browse/TOKEN?publisher=MAC`.
The broker answers only for an active stay placed on that Mac, and the proxy
rechecks every 10 s, so a token stops working on other hosts and soon after its
stay ends. The
policy is `none`, `named` (exactly the listed hosts) or `open` (any host whose
every IPv4 address is public, so never loopback, the LAN, link-local or CGNAT).
The manifest's `AGENT_NETWORK_ALLOWLIST` describes this rule, not a stay's list,
so changing a host's policy or a stay's sites needs no new image or manifest. The browser verifies the measured compose, image and App Attest
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

Optionally add `"browse":{"default":"named","max":"open","price":{"open_nano_usd_per_second":"5000","named_host_nano_usd_per_second":"100"}}`
to set how open guests' browsers may be. A stay asks for a mode up to `max`;
without an ask it gets `default`. The broker adds the posted surcharge to the
stay's rate. Without this field guests browse nothing beyond the package hosts.
The field reaches the broker in the signed heartbeat.

Optionally add `"region":{"name":"Michigan, US","lat":42,"lon":-84}` to
publish a coarse location on the network map. Coordinates must be whole degrees.
The publisher rereads this field for each signed heartbeat; remove it to opt out.
No IP geolocation is used.

The pool checks physical RAM and cores at startup and refuses a configuration
whose guests exceed the capacity after the reserve, reporting the requested,
physical, reserved and available numbers. Editing the file takes effect on
restart; `--operator PATH` selects another configuration.

Pack the matching guest size by supplying the operator file as the final
argument to `workload.py`. The compose manifest and launch
image's `resource_profiles` bind the memory and vCPU count. Each size uses its
own escrow node class and compose measurement; register the packed class
with `applications/payments/register-class.mjs` before starting the pool.

Each configured slot rotates independently: a replacement starts after 450
seconds, the old guest stops admitting at 570 seconds and exits at 840 seconds.
Up to two generations per slot overlap during handover. Boot registration is
serialized to associate each guest's broker identity with its owned VM. A failed
guest is preserved, retired and replaced. After three consecutive failures a slot
retries with exponential backoff up to 30 minutes; successful retirement resets its failure count. Other slots continue.
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
  --pool-version SOURCE_COMMIT --restart-config SHORT_FRESH_STATE/restart.json \
  --broker https://pod.dstack.soc1024.com/relay-broker \
  --index https://pod.dstack.soc1024.com/private-agent/tunnels
```

For a second pool, use its own state, operator file, relay and publisher keys,
`--max-slots 1 --relay-port 4020 --coexist-pool OTHER_STATE`. The slot cap
also applies after SIGHUP. Pack its workload with a distinct host proxy port
(e.g. `http://192.168.127.254:18485`); the launcher reads that measured port.
The relay binary accepts `-port PORT`. Each slot can overlap two generations.

Stop with `kill -TERM LAUNCHER_PID`. It drains owned guests, preserves logs,
assertions, original result disks and signed receipts, retires temporary disks,
clears its discovery hints, and stops its relay, tunnel and helper. Each
`run-*/evidence/` directory retains the guest evidence and reclaimed-space record.
Broker chain/RPC refusals and unreachable brokers retry after 60 seconds,
doubling to 15 minutes without a retry limit. Guest attestation and result
closure failures retry with backoff up to 30 minutes after three consecutive
failures.
Repeat `--publication-rpc HTTPS_URL` to specify ordered publication providers.
Each failed provider is logged; an ambiguous submission retries the same signed
transaction and checks its receipt before completing.

To supervise a pool with launchd, put its complete command argv in a Mac-local
JSON file, using absolute executable paths and omitting `--state`. Each launch
gets a fresh state directory under the service root. Write a definition, install
it, or uninstall it with:

```sh
python3 applications/compute-node/pool-service.py write \
  --label org.dsmack.pool.staging --root /absolute/staging/service \
  --command /absolute/staging/pool-command.json
python3 applications/compute-node/pool-service.py install \
  --label org.dsmack.pool.staging --root /absolute/staging/service \
  --command /absolute/staging/pool-command.json
python3 applications/compute-node/pool-service.py uninstall \
  --label org.dsmack.pool.staging --root /absolute/staging/service \
  --command /absolute/staging/pool-command.json
```

The agent restarts an exited launcher after launchd's 60-second throttle. Failed
starts back off up to 30 minutes before opening transports; ten minutes with ready
or busy guests resets the backoff. Logs are in the service root. Uninstall allows
the launcher to drain its owned guests.
The service supplies `--restart-config SERVICE_ROOT/restart.json` by default;
an explicit `--restart-config` in the command JSON selects another path.

Restart the pool with `SIGHUP` to the launcher. It validates the replacement's
files, measured base and template hashes and expected workload/compose hashes,
then starts `applications/compute-node/pool.py` from the replacement's `source`
checkout behind the existing relay and proxy. One boot lock
serializes guest identity assignment across generations. A single combined fleet
heartbeat and discovery directory retain the old guests throughout overlap.
After a new ready guest has a live verified broker registration and the combined
heartbeat appears in `/network`, the launcher sends TERM to the old pool. That
pool stops rotating and retains its guests through their measured admission and
`--drain-seconds` windows. A rejected config, failed boot or readiness timeout
keeps the serving pool rotating; the timeout drains only the candidate.

To upgrade a launchd pool without a gap in ready slots, set `SERVICE_ROOT` to
its `--root` and `NEW_SOURCE` to the new checkout's absolute path. Set
`NEW_RUNNER`, `NEW_WORKLOAD`, `OPERATOR` and `SOURCE_COMMIT` to the staged
release. Keep the service checkout and running generations' checkouts available.
Generate the replacement config atomically at the service's restart path:

```sh
RESTART_CONFIG="$SERVICE_ROOT/restart.json"
VENV/bin/python - "$NEW_SOURCE" "$NEW_RUNNER" "$NEW_WORKLOAD" "$OPERATOR" "$SOURCE_COMMIT" <<'PY' > "$RESTART_CONFIG.tmp"
import hashlib, json, sys
from pathlib import Path
source, runner, workload, operator, version = sys.argv[1:]
def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()
w = Path(workload)
print(json.dumps(dict(source=source, runner=runner, workload=workload, operator=operator,
    pool_version=version, workload_sha256=sha(w/'workload.img'),
    manifest_sha256=sha(w/'compose-manifest.json'))))
PY
mv "$RESTART_CONFIG.tmp" "$RESTART_CONFIG"
VENV/bin/python applications/compute-node/pool-service.py reload \
  --label org.dsmack.pool.staging --root "$SERVICE_ROOT" \
  --command /absolute/staging/pool-command.json
```

`reload` sends SIGHUP to the launchd job's existing launcher. The old generation
keeps rotating until a new guest is ready and visible at the broker, then drains
while the new generation fills its remaining slots. The combined heartbeat's
`version` switches to `SOURCE_COMMIT` when the new generation takes over.
Update the command JSON's checkout, runner, workload, operator and pool-version
arguments to the same release for subsequent launchd starts.
During a reload both generations run guests, up to three times the slot count
while the old one rotates. Choose `--max-slots` so that many guests fit in the
Mac's memory after its reserve.

For a manually started launcher, write the same config at its `--restart-config`
path and run `kill -HUP "$(cat "$STATE/launcher.pid")"`.

The replacement must use the existing relay peer, broker and tunnel index;
changes to those shared transports require a separate transport deployment.
`--restart-timeout SECONDS` changes the default 300-second readiness budget.
Only one replacement/drain runs at a time.

For the first upgrade from the legacy launcher, run the new `mac-pool.py` command
above with the **existing** runner, workload, state and transport arguments,
adding `--adopt-launcher "$OLD_LAUNCHER_PID"`. Run it in a new background process
and write stdout to `"$STATE/launcher-mbb.log"`. The handoff freezes the two old
controllers, validates the active guest drivers from their existing launch and
attestation records, and transfers those drivers and transport groups to the new
controller. It kills only the frozen controllers after the new pool acknowledges
ownership. If any old guest is still booting, the command refuses and resumes the
old controllers; retry after that guest attests. After the new launcher writes
`launcher.pid`, create `restart.json` at its `--restart-config` path and send HUP.
No guest, native runner, relay or workload rebuild is needed for this Python-only
upgrade.

With shell variables set to the existing installation, the first handoff command
is (run from the updated checkout):

```sh
nohup "$PYTHON" applications/compute-node/mac-pool.py \
  --runner "$RUNNER" --workload "$WORKLOAD" --state "$STATE" \
  --operator "$OPERATOR" --relay "$RELAY" --relay-key "$RELAY_KEY" \
  --cloudflared "$CLOUDFLARED" --publisher-key "$PUBLISHER_KEY" \
  --publisher-address "$PUBLISHER_ADDRESS" --registry "$REGISTRY" \
  --broker "$BROKER" --index "$INDEX" --pool-version "$(git rev-parse HEAD)" \
  --adopt-launcher "$OLD_LAUNCHER_PID" --restart-config "$STATE/restart.json" \
  > "$STATE/launcher-mbb.log" 2>&1 &
```

Include the existing `--ipfs-bin`, `--ipfs-car`, `--ipfs-state` and
`--publication-rpc` options when present on the legacy command. Use a new stdout
log as above; existing transport logs remain open through the handoff.

### Disk

Below 12 GiB free the pool offers no new slot, retries in five minutes and starts
`dsmack_gc.py gc` once; the launcher waits instead of exiting. Every heartbeat
carries `disk.free_bytes` and `disk.floor_bytes`. A launchd start reaps the
stopped generations under its `--root`: each run no live launcher or process owns
keeps `result.img.gz` (hash-checked) and its logs, and loses its scratch,
workload, staged and partial disks.

`dsmack_gc.py gc` keeps every `~/dsmack-*` directory that a LaunchAgent, a pool
command JSON, a `restart.json`, a running process or `~/.dsmack/gc-pins` (one
path per line) names, plus the directories their symlinks reach, plus the newest
other release as rollback. It removes the other releases (directories with a
`source` checkout or `pool-command.json`), first copying keys, configs, records
and logs under 50 MB to `~/.dsmack/gc-keep/RELEASE/`. `--dry-run` prints the plan.
Stage a release's checkout with `dsmack_gc.py source COMMIT RELEASE/source`
(a worktree of the one bare repo at `~/.dsmack/dsmack.git`) and its images with
`dsmack_gc.py store RELEASE`, which leaves APFS clones of
`~/.dsmack/store/sha256/DIGEST` in place, so identical images across releases
share blocks.

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

## Encrypted artifact pins

`artifact-store.py` serves broker-signed `raw-put` and `raw-get` requests on
loopback using the existing Kubo API. It stores up to 64 MiB across 4096 permanent
artifact pins, with a 512 KiB limit per encrypted block. Its state directory holds
the published CID records; Kubo holds the ciphertext.

Use the operator Python environment containing `eth-account`:

```sh
VENV/bin/python applications/compute-node/artifact-store.py \
  --state ARTIFACT_PIN_STATE --broker-signer BROKER_PAYMENT_SIGNER \
  --ipfs-api http://127.0.0.1:15092 --port 15094
```

Route the broker's `artifactShares.store` URL to port 15094 through the operator's
HTTPS tunnel. The signer is the address returned by the broker's `/payments/key`.
Stop the helper with `kill -TERM PID`; its pins and CID records remain available
when it restarts.
