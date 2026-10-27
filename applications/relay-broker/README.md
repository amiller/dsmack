# Relay broker

A dstack-webhost Deno handler that verifies Mac egress relays and issues Ed25519
byte-budget grants. Traffic goes directly from the libp2p client to the relay.
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
key path as the scoped webhost socket. It generates a local test operator token
in `broker-data/operator.token` and passes its SHA-256 digest and socket path to
the handler over stdin. It keeps the signing seed in memory.
Use `python3 dev.py SOCKET DATA HOST PORT` to choose a listener.

## HTTP API

- `GET /key` → `{"algorithm":"Ed25519","public_key":"<32-byte hex>"}`.
- `GET /relays` → an array of relays with verified attestation details and lease
  expiry. `GET /` shows them with client connection commands.
- `POST /relays`, authenticated with `Authorization: Bearer <operator token>`,
  accepts `{relay_peer, relay_maddr, manifest_sha256, os_image_hash, cdhash,
  attestation}`. `attestation` is the hex guest `/v1/Attest` blob obtained over
  `/dsmack/attest/1` or from the runner's `attestation` artifact. The broker checks
  the approved tuple, caller service, PeerId binding, signed event log, App Attest
  key, assertion signature, build approval and burns before adding it. The circuit
  address ends in `/p2p-circuit/p2p/<relay_peer>`.
- `POST /grant {relay_peer, client_peer, bytes}` → a signed grant. Byte budgets
  are positive integers up to 67,108,864. Unknown/expired relays return 404;
  exhausted credit returns 429. No operator token is needed for free credit.

Operators renew registrations every 30 seconds while their relay is serving;
leases expire after 60 seconds. This is operator-reported liveness, with the
attestation verified at registration. Broker restarts clear registrations;
operators register again. Hourly client quotas persist in `credits.json` in
`ctx.dataDir`, with serialized atomic updates.

Create a registration JSON from a relay's artifact and its admitted measurements:

```sh
python3 - PEER CIRCUIT_ADDRESS MANIFEST_SHA256 OS_IMAGE_HASH CDHASH attestation.bin <<'PY' > registration.json
import json, sys
from pathlib import Path
peer, addr, manifest, image, cdhash, blob = sys.argv[1:]
print(json.dumps(dict(relay_peer=peer, relay_maddr=addr, manifest_sha256=manifest,
                     os_image_hash=image, cdhash=cdhash, attestation=Path(blob).read_bytes().hex())))
PY
BROKER=http://127.0.0.1:18270
curl --fail-with-body "$BROKER/key" > key.json
# OPERATOR_TOKEN is the broker's token on the machine running these commands.
curl --fail-with-body "$BROKER/relays" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @registration.json
curl --fail-with-body "$BROKER/grant" -H 'Content-Type: application/json' \
  --data '{"relay_peer":"PEER","client_peer":"CLIENT_PEER","bytes":1048576}' > grant.json
python3 verify-grant.py key.json grant.json
```

Grants are sorted-key, no-space UTF-8 JSON. Ed25519 signs the canonical object
without `sig`:

```json
{"bytes":1048576,"client_peer":"CLIENT_PEER","expires_at":1793120000,"grant_id":"0123456789abcdef0123456789abcdef","relay_peer":"PEER","v":1}
```

The response adds `sig` as 64-byte lowercase hex, also in canonical key order.
`grant_id` is 16 random bytes as 32 lowercase hex characters. Expiry is the earlier
of five minutes and the relay lease. The relay authenticates `client_peer` through
the libp2p Noise handshake and enforces the byte budget. The relay's measured
configuration pins the public key returned by `/key`.

## Deploy on dstack-webhost

`project.json` selects `runtime: "deno"` and `isolation: "shared"`. The app runs
in webhost's shared Deno runtime. After promotion, it calls `GetKey` on
`/run/broker/relay-broker/dstack.sock` with the safe name `egress-grants-v1` and
algorithm `ed25519`. The webhost proxy fixes its key path to
`/tee-daemon/projects/relay-broker/egress-grants-v1`. Keep the same project name,
key name and dstack application key basis to preserve the signing identity.

Deploy from the laptop, with `config.json` prepared. From this directory:

```sh
bash deploy.sh config.json \
  /absolute/path/to/private-workspace/local-data/relay-broker-20261027/operator.token \
  /absolute/path/to/private-workspace/local-data/relay-broker-20261027/live \
  https://pod.dstack.soc1024.com
```

The script sources `~/.oauth3-prod-secrets.env` without shell tracing, uploads a
source tarball to `POST /_api/projects`, and promotes only `relay-broker`. It
creates the operator token with mode 600 at the supplied laptop path and deploys
only its SHA-256 digest in `ctx.env.OPERATOR_TOKEN_SHA256`. The original token
stays on the laptop. The admin credential is used only for the webhost API.
Deploy evidence contains public responses and project summaries.

The script uses the tarball manifest
`{"name":"relay-broker","source":"tarball://relay-broker","ref":"<commit>","env":{"OPERATOR_TOKEN_SHA256":"<digest>"}}`
and includes `project.json`, the handler modules, configuration, and the shared
assertion verifier. Promotion makes the scoped GetKey socket available; then the
script waits for `/relay-broker/key` and checks `runtime=deno,isolation=shared`.

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
