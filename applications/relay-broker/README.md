# Relay broker

A dstack-webhost Deno handler that verifies Mac relays and compute nodes and
issues Ed25519 byte- or second-budget grants. Jobs and traffic travel directly
over libp2p.
The broker gives each client PeerId four grants and 64 MiB of free testnet credit
per hour. `authorizePayment()` in `broker.mjs` is the payment authorization seam.

## Configure

Run from this directory. Use the exact approved relay compose manifest, runner
CDHash and the broker's eventual public URL:

```sh
python3 - /path/to/compose-manifest.json CDHASH https://WEBHOST/relay-broker <<'PY'
import hashlib, json, sys
from pathlib import Path
manifest, cdhash, url = sys.argv[1:]
raw = Path(manifest).read_bytes()
m = json.loads(raw)
service, = json.loads(m['docker_compose_file'])['services']
c = json.loads(Path('config.example.json').read_text())
c['workloads'] = [{'manifest_sha256': hashlib.sha256(raw).hexdigest(),
                   'os_image_hash': m['base_vm']['os_image_hash'],
                   'cdhash': cdhash, 'service': service}]
c['client_command'] = c['client_command'].replace('https://BROKER_HOST/relay-broker', url.rstrip('/'))
Path('config.json').write_text(json.dumps(c, indent=2) + '\n')
PY
```

`config.json` holds the RPC URL, App Attest registry and canary addresses,
approved workload tuples, and the client command shown on the page.
`{relay_peer}`, `{relay_maddr}`, `{manifest_sha256}`, `{os_image_hash}` and
`{cdhash}` expand for each relay. The template runs the grant-aware client demo
from `applications/egress-relay/demo.py`; run it from a checkout containing that
client with `./dsmack-egress`, `./enrollment` and `./compose-manifest.json` installed.

By default the broker reads the enrolled App Attest public key and counter from
the configured registry, then checks the assertion, CDRegistry approval and
canary burns using `secret-release/policy.mjs`. For an operator-admitted runner
enrolled off chain, verify its Apple certificate chain first:

```sh
python3 enroll.py /path/to/enrollment CDHASH > /tmp/relay-enrollment.json
python3 - <<'PY'
import json
from pathlib import Path
p = Path('config.json')
c = json.loads(p.read_text())
c['enrollments'] = [json.loads(Path('/tmp/relay-enrollment.json').read_text())]
p.write_text(json.dumps(c, indent=2) + '\n')
PY
```

`enroll.py` uses the repository's Apple root, macOS App Attest policy and
intermediate expiry check. The resulting public enrollment pin becomes part of
the deployed source. The broker still verifies every relay assertion itself and
reads build approval and canary burns from the live chain.

## Run locally with dstack

Start `dstack-simulator` in its own directory with its simulator configuration.
Then, from this directory:

```sh
python3 dev.py /absolute/path/to/sim/dstack.sock /absolute/path/to/broker-data
# http://127.0.0.1:18270/
```

Requires Python 3.8+ and Deno (`~/.deno/bin/deno`, or set `DENO`). `dev.py` calls
the simulator through the handler's real `GetKey` call, using the same project
key path as the scoped webhost socket. It passes the socket path to the handler over stdin and keeps the signing seed
in memory.
Use `python3 dev.py SOCKET DATA HOST PORT` to choose a listener.

## HTTP API

- `GET /key` → `{"algorithm":"Ed25519","public_key":"<32-byte hex>"}`.
- `GET /relays` → an array of relays with verified attestation details and lease
  expiry. `GET /` shows them with client connection commands.
- `GET /nodes` lists compute nodes. Their `kind` is `compute`; `relay_peer`
  and `relay_maddr` remain the grant target and circuit address fields.
- `POST /relays` or `POST /nodes` accepts `{kind, relay_peer, relay_maddr,
  manifest_sha256, os_image_hash, cdhash, receipt_key, attestation}`. Compute
  nodes also send their P-256 `secret_key`. Registration needs only attestation.
  The broker verifies the admitted measurements, caller, key bindings, event
  log, App Attest assertion, build approval and canary burns.
- `POST /grant {relay_peer, client_peer, unit, amount, nonce, sig}` issues a
  grant signed by the broker. The client signs the canonical request without
  `sig` with its inline libp2p Ed25519 key. Nonces are 16 random bytes in hex
  and cannot repeat, including across quota windows and broker restarts. `unit` is
  `bytes` (default) or `seconds`. Limits are 64 MiB or 1800 seconds per client
  per hour, and four grants total. Compute grants require `seconds`; relay
  grants require `bytes`. A grant contains `unit` and its corresponding
  `bytes` or `seconds` budget. Unknown/expired peers return 404; exhausted
  credit returns 429. See [the compute protocol](../compute-node/PROTOCOL.md).

Operators renew registrations every 30 seconds while their relay is serving;
leases expire after 60 seconds. This is operator-reported liveness, with the
attestation verified at registration. Broker restarts clear registrations;
operators register again. Hourly client quotas persist in `credits.json` in
`ctx.dataDir`, with serialized atomic updates.

Grants are sorted-key, no-space UTF-8 JSON. Ed25519 signs every field except
`sig`; `sig` is 64-byte lowercase hex. `grant_id` is 16 random bytes as 32 hex
characters. Byte grants expire at the earlier of five minutes and the relay
lease; compute grants expire after five minutes. Guests enforce authenticated
client, target, expiry and budget against their pinned broker key.

## Deploy on dstack-webhost

`project.json` selects `runtime: "deno"` and `isolation: "shared"`. The app runs
in webhost's shared Deno runtime. After promotion, it calls `GetKey` on
`/run/broker/relay-broker/dstack.sock` with the safe name `egress-grants-v1` and
algorithm `ed25519`. The webhost proxy fixes its key path to
`/tee-daemon/projects/relay-broker/egress-grants-v1`. Keep the same project name,
key name and dstack application key basis to preserve the signing identity.

Prepare and apply updates with [deploy-inference.py](INFERENCE-DEPLOY.md).
It retains the encrypted provider environment and existing operator-token hash,
packages the shared Deno handler and its bundled verifiers/transports, and
compares broker/payment keys and secret-release identity after promotion.

The webhost volume at `ctx.dataDir` holds quota state. The Ed25519 signing key is
rederived directly from dstack, independently of the quota file.

## Test

From the repository root:

```sh
node --test applications/relay-broker/broker.test.mjs dstack-compat/secret-release/policy.test.mjs
deno check applications/relay-broker/server.ts
```

The broker tests cover canonical signing, independent Ed25519 verification, the
locked relay's recorded assertion, rejected PeerId/caller/build/enrollment
bindings, expiry, concurrent quotas, persisted quotas and storage failures.
`verify-grant.py` uses Python `cryptography` for independent verification of an
HTTP grant; `--at UNIX_SECONDS` replays verification at an evidence capture time.

## Browser sandbox forwarding

`GET /sandbox/nodes/PEER/attestation?challenge=HEX` fetches the node's current
proof through libp2p. Paid nodes require a fresh 32-byte challenge. The browser
verifies the proof, measurements and keys before sealing any inputs.

`POST /sandbox/jobs` accepts `{node_peer,job_id,grant,sealed,client_peer,signature}`
and returns the sealed node result synchronously. `sealed` is the existing
`{epk,iv,ct}` secret box. The browser signs canonical
`{bundle_sha256,client_peer,grant_sha256,job_id,node_peer}` with its Ed25519 buyer
key. Both hashes are SHA-256 of canonical JSON. The node authorizes this exact
job independently of the forwarder's transport PeerId. A lost HTTP result is
reported as `node_result_lost`; the caller retains its job ID and does not
resubmit it. Node refusals use `grant`, `replay`, `busy`, `bundle`, `execution`
and `attestation`; replay/busy are HTTP 409 and other refusals are 403.

Set `sandbox_forwarder` in `config.json` to the helper's internal HTTP URL and
`browser_origins` to the exact page origins. Set `SANDBOX_FORWARDER_TOKEN` in the
broker context and helper environment when the helper listens beyond loopback.
The helper only receives public admission data and ciphertext.

For local testing, generate keys on the machine that runs the services:

```sh
mkdir -p local-data/sandbox
python3 applications/relay-broker/local-key.py \
  "$PWD/local-data/sandbox/getkey.sock" "$PWD/local-data/sandbox/getkey.seed"
# In another terminal, after writing applications/relay-broker/config.json:
python3 applications/relay-broker/dev.py \
  "$PWD/local-data/sandbox/getkey.sock" "$PWD/local-data/sandbox/broker" 127.0.0.1 18270
# Build and run on zed under /data:
(cd applications/compute-node/peer && go build -o ../../../local-data/sandbox/forwarder ./forwarder)
local-data/sandbox/forwarder -key local-data/sandbox/forwarder.key
```

## Shared Deno web app deployment

The broker forwards sealed jobs directly with its bundled libp2p transport.
`GET /sandbox/transport` reports transport readiness. It creates no helper
container. Package and update the existing broker with `deploy-inference.py`;
see [encrypted provider deployment](INFERENCE-DEPLOY.md). Retain its encrypted
NEAR environment, operator-token hash, payment configuration and signing keys.
Build `applications/private-agent-web` on the Linux builder and use that app's
`deploy.py` to update the existing `private-agent` shared Deno project.

For a new measured sandbox, add its public compose/image/build tuple to
`sandboxDiagnosticWorkloads` for an operator diagnostic, or register a new paid
class through the separate payment workflow. Operator grants use
`POST /sandbox/operator-grant` with the existing operator authentication. They
have no escrow debit. The signed buyer request at `POST /sandbox/capability`
returns a job-scoped capability for sealing to the guest. The broker verifies
NEAR gateway and per-model quotes, pins upstream TLS and encrypts each model
request. The browser and guest never receive the NEAR API key.
