# dstack-compat

dstack's guest API v1 (`/v1/GetKey`, `/v1/Attest`, `/v1/Info`, `/v1/Version` on
`/var/run/dstack.sock`) for a dsmack guest, so one compose file calls one key
API on dstack and on a Mac.

A dstack app (the coordinator) mints a grant per (task, worker): a scoped root
key from its own `GetKey`, signed by its grant signer key. The shim derives
keys from that scoped root with dstack's v1 KDF. `GetKey` returns a four-link
chain: scoped root over the key claim, coordinator signer over the grant, then
the signer's two-link dstack chain to the KMS root. A worker key verifies to
the KMS root through the grant and never verifies as a coordinator key.

In the guest the supervisor starts the shim on the `dsmack-ctl` virtio console
port before any workload exists. The shim sends the app the system events and a
seal; after the seal the app answers only `/v1/Attest`. The app asserts with App
Attest over 255 bytes of client data: `"dsmack.appattest.guest-attest/1" ||
os_image_hash || manifest_sha256 || run || event_head || caller || report_data`,
where `run` is the sha256 of the run's launch-assertion client data, `event_head`
the hash chain over the sealed event log and `caller` the sha256 of the compose
service name. `Attest` returns a dstack `VersionedAttestation` with
`platform.kind = "apple-app-attest"` and `stack.kind = "dsmack"`. On chain,
`AppleAttest.verify(context, proof)` takes `context = sha256(clientData)`
unchanged.

- `dsmack_dstack.py` KDF, claim, grant statement, chain verification.
- `guest_attest.py` event log, client data, `VersionedAttestation` encoding and
  `verify(blob)`, which replays the log and rebuilds the client-data hash for
  the App Attest check. Stdlib only.
- `agent.py --dir <dir> [--ctl <port>] [--event NAME=HEX]... [--canary-key PATH] [--grant grant.json] SERVICE...`
  the shim, serving `<dir>/<service>.sock`. `GetKey` needs `--grant`, `Attest` needs `--ctl`.
  `--canary-key` writes a fresh P-256 key to PATH and sends its public key as the
  `canary-guest-key` system event (Canary kinds Guest and Owner).
- `secret_box.py` opens a task secret sealed to the agent's `secret-key` (P-256 ECDH, HKDF-SHA256,
  AES-256-GCM through the image's libcrypto). With `--secret-key` the agent holds that key in memory,
  sends its public key as the `secret-key` system event before the seal, and serves
  `/v1/GetSecret {task_id, epk, iv, ct}` → `{secret}`.
- `secret-release/` the release policy, one JS module (`policy.mjs`) run as a dstack-webhost handler
  (`server.ts`) or a Lit action (`lit-action.js`). `POST /release {task_id, attestation}` verifies the
  guest Attest attestation (App Attest key enrolled in an `AppleAttestRegistryV1`, cdhash of the approved
  CDRegistry build, counter above the on-chain one, signature over the rebuilt client data, exactly one
  `secret-key` before `system-ready`, the task's manifest and images, `report_data =
  sha256("dsmack.secret-request/1" || task_id) || 0^32`, image and build not burned on the canary) and
  returns the task secret sealed to that `secret-key`. A replayed attestation only yields another
  ciphertext for the same run's in-memory key, so the policy keeps no state.
- `secret_workload.py <repo> <image files> <starter public-tree> <out> <task id> <host:port>` builds a
  workload that attests, asks the policy, and opens the secret through `/v1/GetSecret`.
- `canary_workload.py <repo> <image files> <starter public-tree> <out>` builds the canary
  workload: one `/v1/Attest` with zero `report_data`, written to its outputs, then a sleep.
  Owner canaries bind its manifest sha256.
- `grant.py <dstack.sock> <task> <worker> <compose_hash> <ttl_s>` the coordinator call.
- `docker-compose.json` a stdlib worker that calls `GetKey` and `Info`.
- `e2e.sh <dir>` runs that compose in a docker-in-docker guest twice, once
  against the dstack simulator and once against the shim, then `verify.py`
  checks that both keys reach the same KMS root.

## Run

Tests (needs `coincurve cryptography pycryptodome pytest`):

```sh
python3 -m pytest dstack-compat
```

The secret-release tests (`test_secret_box.py`, `node --test secret-release`) need node.
Run the policy locally:

```sh
SECRET_RELEASE_FILE=config.json deno run --allow-net --allow-read --allow-env \
  dstack-compat/secret-release/server.ts 127.0.0.1 8787
```

`config.json` is `{rpc, attest, canary, tasks: {<task id>: {manifest, images, secret}}}`, hex values.

End to end, on a docker host. `<dir>` holds `sim/` (dstack's
`sdk/simulator` files plus a running `dstack-simulator` built with
`sdk/simulator/build.sh`), `compat/` (this directory) and `pylib/` (the four
packages, `pip install --target`):

```sh
dstack-compat/e2e.sh <dir>
```
