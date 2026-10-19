# Runner ↔ abalone peer interface (v1, 2026-10-08)

The abalone node on a Mac = signed Runner.app (CDHash) + the abalone peer as a compose workload (compose_hash).
The same peer image/compose runs in a dstack CVM; one compose_hash admits both.

Guest-facing endpoints, all on the existing unix socket relayed to `/run/egress.sock`:

1. `POST http://runner.local/attest` body `{"data": "<utf8 string>"}` →
   `{"type":"macrunner","attestation":b64,"keyId":str,"bootClientData":b64,"assertion":b64,"assertClientData":b64}`
   - `bootClientData` is the exact clientData the current enrollment's attestation signed. At boot it is `{app, attested, compose_hash, domain:"mac-compose-boot/1", enrolled_at, eph_pub, nonce, receipt_pub}`; `app` is the app id the build was released under (item 5). The runner re-enrolls (new App Attest key, `attestKey`) every 6 h by default (`--reenroll-seconds`), with no KMS round trip, over `{app, attested:true, compose_hash, domain:"mac-compose-enroll/1", enrolled_at, nonce, receipt_pub}`: the same app, compose_hash, KMS nonce and receipt_pub as the boot. `/attest` always serves the newest enrollment; verifiers accept either domain and refuse an enrollment older than their maximum age (12 h). `enrolled_at` is Unix seconds. keyId and attestation stay in the runner's RAM; nothing is written to disk.
   - `assertClientData` = canonical JSON `{"compose_hash":…, "data":…, "domain":"mac-compose-assert/1"}`; assertion is over sha256 of it. Canonical JSON here and in every runner-made clientData: UTF-8, keys sorted, no whitespace, `/` not escaped (Foundation `JSONSerialization` with `.sortedKeys, .withoutEscapingSlashes`). Verifiers check the signed bytes as received; they need not re-serialize.
   - App Attest calls (assertions and re-enrollments) run one at a time in arrival order; one can take seconds.
   - Verifier: verifyAttestation(attestation, keyId, sha256(bootClientData)) with CDHash allowlist → check bootClientData.compose_hash allowlisted → verifyAssertion(assertion, sha256(assertClientData), pubkey) with CDHash check → assertClientData.compose_hash == bootClientData.compose_hash → assertClientData.data is what the verifier expects (must be `abalone-attest/1|<peerId>|<remotePeerId>|<nonce>`: binding the remote PeerId stops a peer acting as an assertion oracle).
   - Ad-hoc/--no-attest mode returns `{"type":"dev","bootClientData":…,"assertClientData":…}` and peers refuse it unless dev admitted.
   - Verifiers: `runner/verify/macrunner.mjs` (`verifyMacRunner(ev, {cdhashes, composeHashes, expectData})`, JS, for abalone) and `runner/kms/verify_attest.py` (Python, used by `test/attested.sh`).
2. `CONNECT host:port` (HTTP/1.1 CONNECT on the same socket) → raw TCP tunnel, only to `egress.tcp` entries `{"host","port"}` in app-compose.json. For libp2p (Noise is end to end). Refused otherwise with 403.
3. Existing HTTP proxy rules (`egress.allow`) for providers: the runner injects the provider key; the guest never has it.
4. Receipts: proxied provider exchanges may carry a provider quote hash. Rule field `"provider_quote": {"kind": "redpill"|"phala"|"nearai", "attestation_url": …, "compose_hashes": [accepted…] | "onchain": {"rpc", "apps": [DstackApp…]}, "model": … (nearai only)}` makes the runner fetch and verify the provider's attestation before the first request to that host and put `provider_quote_sha256` (and, for `onchain`, `onchain: {rpc, block, apps}`: the Base block checked and the DstackApp that admitted each measured compose) in each receipt for it. `onchain` admits a measured compose when its measured app-id is in `apps` and `allowedComposeHashes` on that app is true at one block read through the pinned `rpc`; abalone's NEAR rule uses NEAR's gateway and models apps. `provider_quote_sha256` = sha256 of the exact response body bytes of the attestation report the runner fetched and verified. Every rule naming a host carries the same `provider_quote`; it is verified once per host per boot. The runner then pins that host's TLS connections to the SPKI sha256 the quote attests (ACI: `workload_keyset.tls_public_keys` for the host; NEAR: `gateway_attestation.tls_cert_fingerprint`); a leaf outside that set is refused (502). On verification failure, requests are refused (502) with no upstream contact. NEAR's report endpoint needs the provider key: the runner hands it to its verifier helper on stdin.

Provider keys: the KMS reads them itself from the abalone key store on the mini (`--keys-file <path> --provider <id> [--label L]`, lib/nodekeys.mjs format `{active:{<provider>:<label>}, keys:[{kind,provider,label,key,added}]}`; without `--label`, `active[provider]`), never printed or logged. Missing file, missing active label, or anything but exactly one matching entry = hard error.

5. `POST http://runner.local/key` body `{"path": "<utf8>"}` → `{"key": "<64 hex>"}`: a stable sealed secret, the analogue of dstack `get_key`.
   - The KMS holds a master secret, persistent and never logged (`<--state>/master.key`, 32 bytes, mode 0600, made on first run). Its allowlist admits builds (cdhash, compose_hash) to apps, `--allow APP:CDHASH:COMPOSE_HASH`, one app per build. It derives `app_key = HKDF-SHA256(master, info="mac-compose-app-key/1|" + APP)` (no salt, 32 bytes) and returns it inside the encrypted parcel alongside the API key. The sealed plaintext is JSON `{"api_key": <str>, "app": <APP>, "app_key": <64 hex>}`; the runner refuses any other key set and any `app` other than its `--app`. `cdhash` comes from the verified attestation; in dev mode the literal string "dev" is used. The genesis app id of a build is `"<cdhash>|<compose_hash>"`, which reproduces the pre-app derivation (`"mac-compose-app-key/1|" + cdhash + "|" + compose_hash`) byte for byte, so a peer started before app ids keeps its keys.
   - The runner returns `HKDF-SHA256(app_key, info="mac-compose-get-key/1|" + path, 32 bytes)`.
   - The same app and KMS give the same key across boots and across every build admitted to the app (an upgrade keeps the PeerId, slice and eth keys). A different app gives a different key.
6. `GET http://runner.local/provider-quote?host=<host>` → the exact attestation report bytes whose sha256 is that host's `provider_quote_sha256`. 404 if no request to that host has triggered a quote fetch yet; 502 with the reason if verification failed. The peer re-verifies those bytes itself and checks that their sha256 matches the receipts.
7. Persistent ledger directory: the peer's compose service declares `"volumes": ["<name>:/abalone-ledger"]` and top-level `"volumes": {"<name>": {}}` (named volume only; host binds and options are refused). The peer runs with `--ledger /abalone-ledger`. The runner keeps an unencrypted 256 MiB ext4 image per (app, name) under `<base>/volumes/<sha256(app)>/<name>.ext4`, made on first boot and reused after, so the directory survives reboots and upgrades within the app, as the PeerId does; a new app starts empty. A genesis app id `"<cdhash>|<compose_hash>"` uses the pre-app directory `<base>/volumes/<cdhash>/<compose_hash>/` if it exists, for every build admitted to it, so a peer from before app ids keeps its ledger across an upgrade. The runner holds an exclusive `flock` on `<name>.ext4.lock` beside each image for its lifetime and refuses to boot if another runner holds it: one live build per app. The marker below still names the booting build's compose_hash, not the app. Each boot the runner places `/abalone-ledger/.abalone-persistent` (read-only file mount) containing the compose_hash in hex and a newline; the peer checks it before trusting that its ledger persists. The Mac owner can read, edit, copy back or delete the image (roll the ledger back). The volume holds the gift ledger only: anything secret the peer needs comes from `/key`, and nothing on the volume may be the only copy of a secret.
8. Task guests. The peer compose declares
   `"tasks": {"images": [<@sha256-pinned>…], "max_concurrent": N, "resources": {<id>: {"cpus", "mem_mb", "out_mb", "max_seconds"}}}`
   at top level, so its compose_hash covers the admitted images and the resource menu (`max_seconds` ≤ 1800; `small` is
   2 / 2048 / 1024 / 1800). `runner check` validates it. Task images are loaded with `--task-archive PATH` (repeatable;
   each archive's manifest digest must be one of `tasks.images`); an admitted image that was not loaded is pulled by digest.
   All on `/run/egress.sock`, host `runner.local`; a compose without `tasks` gets 403.
   - `POST /task/start {task_id: 32 hex, compose: {…}, inputs_tar_b64}` (body ≤ 28 MiB, tar ≤ 20 MiB; every other route ≤ 1 MiB)
     → `{compose_hash, state:"booting", task_id}`. The task compose is serialized as canonical JSON; those bytes are
     `guest/app-compose.json` and `compose_hash` is their sha256. Refused (403) unless: it parses as a runner compose,
     the image is in `tasks.images`, `egress` is empty (`allow` and `tcp` empty, both caps 0), no volumes, `kms_enabled`
     is false, `task` is exactly `{"resource": <menu id>}`, and the labels carry `abalone.task_id` (= task_id),
     `abalone.auth_hash` and `abalone.inputs_root`. Same task_id and compose again: the first answer, no second VM;
     another compose: 409. More than `max_concurrent` booting or running: 429.
   - The VM: its own Containerization container, the resource's vCPUs and memory, 2 GiB rootfs, `/in` = ext4 made from
     the inputs tar, mounted `ro` (also read-only at the virtio device); `/out` = empty ext4 of `out_mb`; no NIC, no
     socket. `command` replaces the image argv as for the peer. stderr goes to `<out>/tasks/<id>/stderr.txt` on the host only.
   - Boot evidence: `clientData = {attested, compose_hash, domain:"mac-compose-task-boot/1", nonce: 32 random bytes hex, receipt_pub}`
     with a fresh in-RAM P-256 receipt key. Task VMs are not separately App Attested: `guest/attest.json` is the `/attest`
     shape with `assertClientData` = that clientData, i.e. the runner's assertion over sha256(clientData) under the peer's
     current enrollment (whose `bootClientData` names the peer compose_hash). The domain is distinct so that `/attest`
     cannot produce a task binding: `/attest` always wraps the peer's data in `mac-compose-assert/1`, and a verifier that
     accepted that would accept any receipt key the peer chose. `verify_receipts.py --task` requires
     `mac-compose-task-boot/1` for both `clientData.bin` and the asserted bytes. `--no-attest`: `{"type":"dev", bootClientData, assertClientData}`.
   - `GET /task/status?id=` → `{dropped_bytes, exit_code, reason, started_at (ms), state, task_id, wall_seconds}`.
     `state` ∈ booting, running, exited (entrypoint exited by itself), stopped (`reason` stop, time_cap or runner_exit),
     failed (`reason` = the error). `wall_seconds` counts from container start, rounded up.
   - `CONNECT task-<id>.runner.local:1` → 200, then raw stdin/stdout. One at a time (second: 409); 409 once terminal.
     Stdout with no connection open goes to a 4 MiB buffer that drops its oldest bytes (`dropped_bytes`), flushed on the
     next attach. Closing does not close stdin. When the entrypoint exits the runner closes the connection 1 s after
     the last write (closing right after a write can lose bytes in the guest socket relay).
   - `POST /task/stop {task_id, grace_seconds 0…300}`: SIGTERM, SIGKILL after the grace (0: SIGKILL at once). Idempotent;
     answers the status. The wall cap is the same stop with grace 5 s and reason `time_cap`.
   - `GET /task/collect?id=` (exited or stopped, else 409): `guest/{app-compose.json, attest.json, clientData.bin, receipts.jsonl}`
     and `out/`, written once when the task ends. `/out` is read on the host from the ext4 image after the VM stops.
     Tar format (both the collect tar and the out tar): ustar, entries sorted by UTF-8 name, directories `name/` mode 0755,
     files 0755 if any execute bit else 0644, uid/gid/mtime 0, empty uname/gname, no pax headers, names over 100 bytes
     split at the first `/` that leaves ≤ 100, two zero blocks at the end. Anything in `/out` other than regular files and
     directories fails the task.
   - `POST /task/delete {task_id}` (terminal only, else 409): removes the run dir and container root; status then 404.
   - Receipts (`guest/receipts.jsonl`, domain `mac-compose-receipt/1`, the task compose_hash, signed by the task's
     receipt key): `{event:"task-start", inputs_sha256}`, `attach`, `detach`, then `{event:"exit", exit_code, wall_seconds,
     out_sha256, reason}`, `out_sha256` = sha256 of the out tar (the `out/` entries alone in the format above). A
     connection open at exit gets its `detach` before `exit`. Verifier: `kms/verify_receipts.py COLLECT_DIR --task
     --peer-compose peer.json (--cdhash H | --dev-unattested)`, run on an extracted collect tar.
   - When the peer exits, the runner SIGKILLs running tasks (reason `runner_exit`) and waits for them to finish.
9. Connections on `/run/egress.sock` that send no request head within 2 s are closed by the runner (logged; 10 s before 2026-10-09). Reason:
   Containerization's guest relay (vminitd `VsockProxy`) can stall a connection opened while another VM in the process
   starts; it then relays no bytes, and every later connection from that guest waits behind it until the host closes it.
   A client sees the close before any response and may retry the request (nothing of it reached the runner). The runner
   ignores SIGPIPE: the host relay writes with `write(2)` on sockets without `SO_NOSIGPIPE`, and a write into a closed
   connection killed the process.
