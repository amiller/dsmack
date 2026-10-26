# Coordinator

A dstack app that holds the keys and the agent heads. Macs run the turns.

Every key comes from the app's own `GetKey` on `/var/run/dstack.sock`:

- `dsmack-release-authority/1` (ed25519) signs alpha releases and per-attempt
  workload admissions. Its key id is `dsmack-coordinator-<first 16 hex of the public key>`.
- `agent-app-key/1/<agent>` (ed25519 seed) is the agent's `app_key`, released to turns.
- Worker grants per (task, Mac key), minted by [dstack-compat/grant.py](../../dstack-compat/grant.py).

State (agents, heads, state blobs, nonces, signed releases, used attempt ids,
admitted compose hashes, enrolled Mac keys and their counters)
is in `/state`, the app's encrypted volume.

## API

Turns speak the mac-compose runner's KMS protocol. Point the runner at
`--kms http://<coordinator>/turn`.

- `GET /turn/nonce`
- `POST /turn/release`: the runner's launch request. Checks the App Attest
  attestation against Apple's root under the macOS policy, that `CDRegistry.rpIdHash`
  of the attested CDHash is our RP ID, that the compose hash is an agent's current
  head, and the nonce. Returns `epk` and `sealed` (`{api_key, app_key}`, as the
  runner expects).
- `POST /turn/commit`: the guest's `{ciphertext, evidence, state_in, state_out, turn}`.
  Checks the launch attestation and the assertion over the transition, then
  advances the head once. A second commit from the same parent is `403 stale_head`.
- `GET /turn/state/<sha256>`: a state blob.
- `POST /grant {task_id, key_id, compose_hash, run, seal_pub, assertion}`: the v3 runner
  app's worker-grant request ([dstack-compat](../../dstack-compat/README.md)). Checks the
  App Attest assertion over the request by an enrolled key, above its last counter, from a
  CDRegistry-admitted build, and that this app admitted a workload with that compose hash.
  Returns the grant with its root key sealed to `seal_pub`.
- `GET /head/<agent>`, `GET /compose/<agent>`: the head and the compose a turn from it runs.
- `GET /keys`: the release key, its dstack signature chain and the app id.

Operator calls carry `Authorization: Bearer $OPERATOR_TOKEN`:

- `POST /agent {agent, image, port, ciphertext}`: create an agent at its genesis blob.
- `POST /sign-release {inventory}`: sign an alpha release inventory with `key_id` set to ours.
- `POST /admit {release_inventory_sha256, profile, closure_context, workload_disk}`:
  one `dsmack-alpha-workload-admission/1` per attempt id, for a profile of a release this app signed.
- `POST /enroll {attestation, key_id, client_data}`: record a Mac's App Attest key for `/grant`.

Environment: `OPERATOR_TOKEN`, `API_KEY`, `RPC_URL`, `CDREGISTRY`.

## Run

Build from the repository root and deploy `docker-compose.json` as a dstack app:

```sh
docker build -t dsmack-coordinator:local -f applications/coordinator/Dockerfile .
```

`e2e.sh <dir>` runs it on a docker host against the dstack simulator. `<dir>` holds:

- `sim/`: `dstack-simulator` built from dstack `sdk/simulator/build.sh`, with that directory's config files;
- `bin/`: `anvil` and `cast`;
- `cdreg/`: `cdregistry.bin` (CDRegistry creation bytecode) and `args.json`
  (`contracts/cd_args.py` on the installed mac-compose runner binary);
- `src/`: this repository;
- `mac/`: `release.json` and `profile.json` of an installed alpha release, and
  `disk.json`, any workload admission (for its `workload_disk`).

It replays the turns in `agent-turns/testdata/personal-agent`, restarts the app,
and mints one admission into `<dir>/out/admission`. Check that admission on the
Mac with the alpha coordinator's verify path:

```sh
ssh mini-mesh python3 -I - <admission dir> <install dir> < applications/coordinator/alpha_check.py
```
