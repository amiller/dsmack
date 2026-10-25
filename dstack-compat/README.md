# dstack-compat

dstack's guest API v1 (`/v1/GetKey`, `/v1/Info`, `/v1/Version` on
`/var/run/dstack.sock`) for a dsmack guest, so one compose file calls one key
API on dstack and on a Mac.

A dstack app (the coordinator) mints a grant per (task, worker): a scoped root
key from its own `GetKey`, signed by its grant signer key. The shim derives
keys from that scoped root with dstack's v1 KDF. `GetKey` returns a four-link
chain: scoped root over the key claim, coordinator signer over the grant, then
the signer's two-link dstack chain to the KMS root. A worker key verifies to
the KMS root through the grant and never verifies as a coordinator key.

- `dsmack_dstack.py` KDF, claim, grant statement, chain verification.
- `agent.py <grant.json> <socket>` the shim.
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

End to end, on a docker host. `<dir>` holds `sim/` (dstack's
`sdk/simulator` files plus a running `dstack-simulator` built with
`sdk/simulator/build.sh`), `compat/` (this directory) and `pylib/` (the four
packages, `pip install --target`):

```sh
dstack-compat/e2e.sh <dir>
```
