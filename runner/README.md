# runner: dstack-style compose workloads on an App Attest Mac (prototype)

`runner` boots one container from a dstack `app-compose.json` in a Virtualization.framework VM
through Apple's Containerization package (0.33.4). The guest has no network device. Its only
egress is a unix socket relayed into the guest at `/run/egress.sock`, where it speaks plain
HTTP to a proxy inside the runner. The proxy holds the API key, originates upstream TLS itself
against pinned anchors, and signs a receipt for each exchange.
Test results: `RESULTS.md`.

## What the runner does, in order

1. `compose_hash = sha256(app-compose.json bytes)`, the same definition as dstack-vmm
   (`vmm/src/app/qemu.rs`, `app_compose_hash`) and dstack-util (`system_setup.rs`, `measure_app_info`).
2. Refuses the compose unless: `runner` is `docker-compose`; no `pre_launch_script`, `bash_script`
   or `docker_config`; `docker_compose_file` is JSON (the JSON subset of YAML; no YAML parser here)
   with exactly one service using only `image`, `command`, `environment`, `volumes` (named volumes only, see
   [Named volumes](#named-volumes)); the image ends in
   `@sha256:<64 hex>`; an `egress` policy is present. `command` is the full argv (the image
   entrypoint is not prepended, unlike docker compose).
3. Checks the kernel file against a digest compiled into the binary. Builds a fresh initfs per boot
   from a digest-pinned `vminit` 0.33.4 (version-matched to the library).
4. Makes two P-256 keys in RAM (receipt signing, key release), gets a nonce from the KMS, and builds
   `clientData = {app, attested, compose_hash, domain:"mac-compose-boot/1", enrolled_at, eph_pub, nonce, receipt_pub}` (canonical JSON),
   `app` being `--app` (see [Apps](#apps-keys-and-volumes-by-app-id)).
   With `--attest`: App Attest `generateKey` + `attestKey(sha256(clientData))`, sent to the KMS.
   With `--no-attest` (DEV-ONLY): no attestation.
5. Receives the API key and the app key sealed to `eph_pub` and opens them in process memory only. The plaintext is
   JSON `{"api_key", "app", "app_key"}`; any other key set, or an `app` other than `--app`, is refused. The KMS reply is
   `{"epk": b64(one-time KMS P-256 point), "sealed": b64(nonce ‖ ciphertext ‖ tag)}`: ECDH(epk, eph),
   HKDF-SHA256 (no salt, info `mac-compose-key-release/1`, 32 bytes), AES-256-GCM, AAD `sha256(clientData)`.
   The key never crosses the localhost socket in plaintext, in either mode.
6. With `--oci-archive`, loads the image from a local OCI layout tarball (see below).
7. Serves the proxy on `<out>/egress.sock`, relays it into the guest at `/run/egress.sock`,
   boots the container with `networking: false` (no NIC, no Rosetta, no virtiofs), waits for exit.

The proxy, per request: matches (host, method, path prefix) against `egress.allow`; refuses `..`
and `%2e` in the path; strips inbound `Authorization`, `Proxy-Authorization`, `x-api-key`, `Cookie`
and hop-by-hop headers; injects the key into the rule's `auth_header`; follows no redirects; uses
an ephemeral URLSession with no system proxy, no cookies, no cache, and a trust delegate that sets
the anchors in `Sources/runner/Anchors.swift` (Amazon Root CA 1, GTS Root R4) with
anchors-only. It enforces `max_requests` per boot and, when the body is JSON with `max_tokens` or
`max_completion_tokens`, reserves that many tokens and refuses the request if they exceed the remaining
`max_tokens` budget (a rule with `"metered": true` requires the field). On a metered rule the reservation is
then settled to the response's `usage`: `total_tokens` (OpenAI), else `input_tokens + output_tokens`
(Anthropic). A metered response without `usage` is refused to the guest (502) and the reservation stays charged.
A policy `host` may include a port (`localhost:8443`); it must equal the guest's `Host` header exactly. Any literal copy of the key in a response body is replaced
with `[REDACTED-API-KEY]` before it reaches the guest. Only `Content-Type` is forwarded back.

Receipt (one JSON line per forwarded exchange, in `<out>/receipts.jsonl`):
`{"body": "<json>", "sig": "<DER ECDSA-P256-SHA256 over body bytes, hex>"}`, where body is
`{compose_hash, domain:"mac-compose-receipt/1", method, url, status, seq, prev, req_sha256, resp_sha256}`,
`prev = sha256(previous body)` (64 zeros for the first), `req_sha256 = sha256("METHOD url\n" ‖ request body)`,
`resp_sha256 = sha256(bytes returned to the guest)`; metered exchanges add `tokens_reserved` and `tokens_charged`.
Refused requests produce no receipt. A rule with `provider_quote` adds `provider_quote_sha256`, and with `onchain` also
`onchain: {rpc, block, apps}` (see Provider quotes).

## Abalone node interface

Spec: `notes/abalone-node-interface.md`. The guest reaches all of these on `/run/egress.sock`.

- `POST http://runner.local/attest {"data"}`: an App Attest assertion over `sha256(assertClientData)`, with the current
  enrollment (attestation, keyId, its clientData). Calls are serialized. With `--attest` the runner re-enrolls every
  `--reenroll-seconds` (default 21600, 6 h) without the KMS: a new key attested over
  `{app, attested, compose_hash, domain:"mac-compose-enroll/1", enrolled_at, nonce, receipt_pub}`. Enrollment evidence lives in RAM
  only; the out dir gets `clientData.bin` (the boot clientData) and nothing else from App Attest. A failed
  re-enrollment exits the runner. `--no-attest` answers `{"type":"dev",…}`. Verifiers: `verify/macrunner.mjs`
  (with the vendored `verify/vendor/appattest.mjs`) and `kms/verify_attest.py`.
- `POST http://runner.local/key {"path"}`: `HKDF-SHA256(app_key, info "mac-compose-get-key/1|<path>")`, where the KMS
  derives `app_key` from its master secret and the app the build is admitted to (see [Apps](#apps-keys-and-volumes-by-app-id)).
- `CONNECT host:port`: a raw TCP tunnel, only to an `egress.tcp` entry; anything else gets 403. curl's
  `--unix-socket` ignores `-x`/`-p`, so the test drives it from node in the abalone peer image.
- `GET http://runner.local/provider-quote?host=H`: the exact report bytes behind that host's `provider_quote_sha256`
  (404 before the first fetch, 502 if it failed).

```json
"egress": {"max_requests": 8, "max_tokens": 0,
  "tcp": [{"host": "127.0.0.1", "port": 8794}],
  "allow": [{"host": "api.redpill.ai", "method": "GET", "path_prefix": "/v1/models",
             "provider_quote": {"kind": "redpill", "attestation_url": "https://api.redpill.ai/v1/aci/attestation",
                                "compose_hashes": ["0637b3d5…"]}}]}
```

A NEAR rule names the DstackApps it trusts instead of compose hashes:
`"provider_quote": {"kind": "nearai", "attestation_url": "https://cloud-api.near.ai/v1/attestation/report", "model": …,
"onchain": {"rpc": "https://mainnet.base.org", "apps": ["0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae", "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"]}}`
(NEAR's gateway and models apps on Base).

### Provider quotes

Before the first request to a `provider_quote` host the runner runs `verify/provider_quote.mjs` with `--node`, after
checking the file's sha256 against `Sources/runner/Pins.swift` (update both together). The helper:

Each measured compose is admitted one of two ways; a rule has exactly one (`runner check` refuses both or neither):

- `compose_hashes`: the measured compose-hash is in the list.
- `onchain: {rpc, apps}`: the helper calls `eth_blockNumber` on `rpc` once, then for each measured compose requires
  the measured app-id to be in `apps` (lowercase `0x` addresses) and an `eth_call` of `allowedComposeHashes(bytes32)`
  (selector `0x2f6622e5`) on that app at that block to return true. Any other result, an RPC error or a TLS failure
  refuses. The RPC is plain JSON-RPC over `node:https` trusting only the runner's anchors (`Anchors.swift`, passed to
  the helper as an argument); mainnet.base.org chains to GTS Root R4 through WE1, already anchored. The helper output
  and every receipt for the rule carry `onchain: {rpc, block, apps}`, `apps[i]` being the app that admitted
  `compose_hashes[i]`; `kms/verify_receipts.py` checks the receipt copy against the saved helper output.

Both modes read the compose-hash (and app-id) from the RTMR3 event log's pre-system-ready events and require each
payload to match its digest, `sha384(u32le(event_type) ‖ ":" ‖ name ‖ ":" ‖ payload)`; aci-verifier's replay covers
the digests only. Under `onchain`, provider code is admitted by whoever controls NEAR's DstackApps (their owner's
governance), as of the block checked, as reported by the pinned public RPC. An RPC that lies about state is not
detected (no light client or proof check).

- `redpill`, `phala` (ACI `aci/1`): `GET <attestation_url>?nonce=<fresh>`; with `@phala/aci-verifier` 0.7.2 and
  `@phala/dcap-qvl` 0.6.6 it checks the TDX quote to the Intel root with Intel PCS collateral and TCB `UpToDate`,
  `report_data` = sha256 of the ACI statement for the keyset digest and our nonce, keyset expiry, the RTMR3 replay,
  and that the measured compose is admitted. The SPKI pins are the keyset's `tls_public_keys` for the host.
- `nearai`: ported from an earlier NEAR client; the runner passes the API key on stdin (NEAR's report endpoint
  needs it). Gateway and every model quote, address/TLS-fingerprint/nonce binding in `report_data`, keccak address
  check, GPU nonce and NRAS verdict, every measured compose (gateway and each model) admitted. The SPKI pin is the
  gateway's `tls_cert_fingerprint`.

The runner keeps the report bytes in RAM, writes the helper output to `<out>/provider-quote-<sha16>.json`, and pins
the host: the TLS delegate refuses a leaf whose SPKI sha256 is not attested. A failed quote refuses every request to
that host with 502 before any upstream contact. Known gap: the CDHash covers the runner and the helper's hash, not
node or `verify/node_modules`.

Pinned anchors added for this (`Sources/runner/Anchors.swift`): ISRG Root X1 (api.redpill.ai, tee.redpill.ai,
inference.phala.com, cloud-api.near.ai, through the ISRG Root X2 cross-cert they serve), GTS Root R1
(nras.attestation.nvidia.com) and Sectigo Public Server Authentication Root R46 (api.trustedservices.intel.com and
certificates.trustedservices.intel.com, Intel PCS), so a guest can also reach NRAS and PCS through plain `egress.allow`
rules without auth injection. GTS Root R4 already covers openrouter.phala.com.

### Task guests

A peer compose with a top-level `tasks` block can start per-task VMs through `runner.local/task/*` and
`CONNECT task-<id>.runner.local:1` (spec: `notes/abalone-node-interface.md` item 8).
Each task is a second Containerization container booted by the same runner
process: no NIC, no socket, `/in` read-only from the inputs tar, `/out` an empty ext4 volume, the resource menu's
vCPUs, memory and wall cap. Its stdin/stdout is the attach stream. After the entrypoint exits the runner stops the VM,
reads `/out` from the ext4 image with `ContainerizationEXT4`'s reader, and writes `collect.tar` once (deterministic
ustar), so `/task/collect` returns the same bytes on every call.

Task VMs are not App Attested themselves. Each gets a fresh receipt key and a boot clientData (domain
`mac-compose-task-boot/1`) naming its compose_hash; the runner signs sha256 of that clientData with an App Attest
assertion under the peer's enrollment. The domain differs from `/attest`'s `mac-compose-assert/1`, so a peer cannot
turn an `/attest` answer over data of its choosing into a task binding; the verifier refuses one. That evidence,
the task compose, the clientData and the task's receipt chain (`task-start`, `attach`/`detach`, `exit` with
`out_sha256`) are `guest/` in the collect tar. `kms/verify_receipts.py DIR --task --peer-compose peer.json --cdhash H`
checks the chain Apple root → runner CDHash → peer compose (which admits the image) → task compose → receipts →
`out/`.

```json
"tasks": {"images": ["abalone-task@sha256:…"], "max_concurrent": 2,
  "resources": {"small": {"cpus": 2, "mem_mb": 2048, "out_mb": 1024, "max_seconds": 1800}}}
```

`--task-archive PATH` (repeatable) loads a task image from an OCI layout tarball, like `--oci-archive`, and refuses one
whose manifest digest is not in `tasks.images`. The test task image is `test/task-image/` (alpine plus a shell
NDJSON echo entrypoint), built on the laptop with
`SOURCE_DATE_EPOCH=0 docker buildx build --builder <docker-container builder> --platform linux/arm64 --provenance=false --sbom=false --output type=oci,dest=task-test.oci.tar,rewrite-timestamp=true test/task-image`
(COPY only, so no emulation; the digest is reproducible) and copied to `../oci/task-test.oci.tar`. The real
abalone task image is `../oci/task.oci.tar`. The test driver is node in
the peer image (`TASKS` and `REAL` in `test/gen_compose.py`); the checks are `test/task_checks.sh`, sourced by both passes.

### OCI archive

`--oci-archive PATH` extracts an OCI layout tarball, loads it into the image store (`ImageStore.load(from:)`), and
refuses unless it holds one manifest whose digest is the compose image's `@sha256:`. It then tags it with the compose
image reference, so `ContainerManager` finds it locally. `command` still replaces the image entrypoint.

### Named volumes

A service may list named volumes, `"volumes": ["ledger:/abalone-ledger"]`, each declared top-level as
`"volumes": {"ledger": {}}`, as docker compose requires. Both live in `docker_compose_file`, so `compose_hash` covers
them, and the same compose runs unchanged under dstack. Host binds (`/x:/y`, `./x:/y`), options (`:ro`), driver
settings and undeclared or unused names are refused.

The runner backs each one with a 256 MiB ext4 image at `<--base>/volumes/<sha256(app)>/<name>.ext4`,
formatted with Containerization's `EXT4.Formatter` on first use, attached as a virtio block device and mounted
read-write at the target. Every admitted build of an app uses the same image, so an upgrade keeps the ledger. A genesis
app (`--app` of the form `<cdhash>|<compose_hash>`, the id of a build from before app ids; `cdhash` is a runner's full
SHA-256 CDHash from `SecCodeCopySigningInformation` `cdhashes-full`, or `dev`) uses the pre-app path
`<--base>/volumes/<cdhash>/<compose_hash>/` instead if that directory exists, whichever admitted build of the app is
booting, so a ledger made before app ids is found where it is after an upgrade; nothing is copied. Before attaching, the runner takes an exclusive non-blocking `flock` on
`<name>.ext4.lock` next to each image and holds it until it exits (not on the image itself: VZ then refuses the attach
with "The storage device attachment is invalid"); if another runner holds it, the boot is refused (`volume <name> at <img> is
locked (...): another runner of app <app> is live; refusing to boot`). That is the "one live build per app" rule, and it
also stops two boots of one build mounting one image twice. Task `/in` and `/out` are per task and not locked. The
image is unencrypted (see RESULTS, Limits). The volume root is owned by
root, mode 0755; the abalone peer image runs as root. Docker's copy-up of image content into an empty volume is not
done.

Each boot the runner writes the compose_hash (hex, newline) to `<--out>/volume-markers/<name>/.abalone-persistent`
and file-mounts it, with option `ro`, at `<target>/.abalone-persistent`. The peer reads it to confirm its ledger
directory is a persistent volume. ContainerizationEXT4 cannot edit an existing image and `exec` works only after the
workload has started, so the marker is a mount over the volume rather than a file inside it.

### Apps: keys and volumes by app id

As in dstack, keys belong to an app, not to a build. An app is a name with a set of admitted builds, each a
(cdhash, compose_hash) pair, and the KMS allowlist names the app: `kms.py --allow APP:CDHASH:COMPOSE_HASH`, repeatable;
a build may appear in one app only (the KMS refuses to start otherwise). The KMS derives
`app_key = HKDF-SHA256(master, info "mac-compose-app-key/1|" + APP)` and seals `{"api_key", "app", "app_key"}`.
An upgrade is admitting the new build under the same app: its `/key` values (PeerId, slice, eth) and its volume are
the old build's. Retiring a build is removing it from `--allow`; the KMS refuses its next `/release`, and the volume
lock covers a retired build still running.

The runner takes `--app APP` (required) and puts it in the boot clientData; the KMS refuses a build admitted to another
app (`build_not_in_requested_app`) and the runner refuses a parcel naming another app. `verify_receipts.py` and
`verify_attest.py` print the app. Clients keep admitting builds by (cdhash, compose_hash); the app is evidence for
receipt readers, not something they need to check.

The genesis id of an app is `<cdhash>|<compose_hash>` of its first build, and `--allow CDHASH:COMPOSE_HASH` is
shorthand for that app. Its info string is then `mac-compose-app-key/1|<cdhash>|<compose_hash>`, byte for byte the
derivation before app ids, so a peer started before this change keeps its PeerId when relaunched with
`--app "<cdhash>|<compose_hash>"`. In dev mode the builds' cdhash is `dev`: `--allow APP:dev:COMPOSE_HASH`, or
`--allow-compose COMPOSE_HASH` for the genesis app `dev|<compose_hash>`.

### KMS key store and master secret

`kms.py --state DIR` (required) keeps `DIR/master.key` (32 random bytes, 0600, made on first run, never logged).
The API key comes from `KMS_API_KEY` or `--keys-file PATH --provider ID [--label L]` (abalone's
`{active, keys:[{kind, provider, label, key, added}]}`; default label `active[provider]`; exactly one match or the KMS
exits). `--dev-omit-app-key` (DEV-ONLY, with `--dev-unattested`) seals a parcel without `app_key`, for the refusal test.

## Compose `egress` field

```json
"egress": {"max_requests": 8, "max_tokens": 1000, "allow": [
  {"host": "httpbin.org", "method": "GET", "path_prefix": "/anything/", "auth_header": "Authorization", "auth_prefix": "Bearer "},
  {"host": "httpbin.org", "method": "POST", "path_prefix": "/anything/v1/messages", "auth_header": "x-api-key", "metered": true}
]}
```

It lives in `app-compose.json`, so it is covered by `compose_hash`. A guest request looks like
`curl --unix-socket /run/egress.sock http://httpbin.org/anything/x`.

## Layout

| Path | What |
|---|---|
| `Sources/runner/main.swift` | CLI, compose loader, KMS client, App Attest, VM boot |
| `Sources/runner/Proxy.swift` | NIO HTTP server on the unix socket, policy, pinned URLSession, receipts |
| `Sources/runner/Anchors.swift` | pinned root certificates (DER) |
| `build.sh`, `entitlements.plist` | ad-hoc build: hardened runtime + `com.apple.security.virtualization` |
| `sign.sh` | signed build: `build/Runner.app` (bundle id `dev.dsmack.provider`, dsmack profile, App Attest CDHash opt-in + VZ entitlement), `build/cdhash.txt` |
| `kms/kms.py` | stand-in KMS: nonce, attested release, DEV-ONLY unattested release |
| `kms/verify_receipts.py` | boot binding + receipt chain verifier |
| `test/fake_upstream.py` | DEV-ONLY HTTPS upstream on localhost:8443 returning `usage`, under a per-run test CA |
| `test/parcel_wrong_key.py` | opens a recorded `/release` body with a wrong key; expects `InvalidTag` |
| `test/gen_compose.py` | writes the test composes with dstack's SDK serializer (laptop) |
| `test/run_tests.sh` | the full ad-hoc test pass: main boot, plus a metering boot with `test/app-compose-meter.json` |
| `test/attested.sh` | the signed/attested test pass (after `sign.sh`) |
| `Sources/runner/Guest.swift` | `/attest`, `/key`, re-enrollment, SPKI extraction, the quote helper runner |
| `Sources/runner/Tasks.swift` | task guests: template check, per-task VM, attach buffer, stop/time cap, `/out` reader, deterministic tar |
| `test/relay_stress.py` | writes a compose that reproduces the guest relay stall during task boots (see RESULTS) |
| `test/task-image/`, `test/task_checks.sh` | test task image (Dockerfile + entry.sh); task checks shared by both passes |
| `evidence/20261008T205959/` | ad-hoc pass with task guests |
| `evidence/20261009T013234/` | ad-hoc pass with the attach-while-booting regression test |
| `evidence/20261008T214329/` | ad-hoc pass after the relay-stall and SIGPIPE fixes and the task-boot domain |
| `Sources/runner/Pins.swift` | sha256 of `verify/provider_quote.mjs` |
| `verify/provider_quote.mjs`, `verify/package*.json` | provider quote helper and its pinned dependencies |
| `verify/provider_quote.test.mjs`, `test/near-report-20261008.json` | on-chain admission check against live Base and a recorded NEAR report (run by `test/run_tests.sh`) |
| `verify/macrunner.mjs`, `verify/macrunner.test.mjs` | JS `/attest` verifier for abalone, and its laptop check |
| `kms/verify_attest.py` | Python `/attest` verifier (used by `test/attested.sh`) |
| `test/replay_report.py`, `test/derive_key.py` | stale-report server; `/key` value recomputed from the KMS master |
| `test/near_diversity.sh` | N NEAR report fetches through the runner; counts distinct signing addresses and TLS fingerprints |
| `evidence/20261008T153752/` | ad-hoc pass with the abalone node interface |
| `evidence/20261008T160103/` | ad-hoc pass with named volumes |
| `test/boot_checks.sh` | workload and receipt checks sourced by both passes |
| `evidence/20261008T143938/` | outputs of the first recorded pass (ext4 images excluded) |
| `evidence/20261008T150144/` | ad-hoc pass with encrypted release and metering |

`kms/*.py` import `verifier/core.py` and `verifier/macos_policy.py` from the repo root
(`REPO = parents[2]`), so run them from a full checkout.

## Run it

On an Apple silicon Mac on macOS 27, with the repository checked out and a Python virtual environment
holding `cryptography` one level above `runner/` (`../.venv`). The runner expects a kernel (`vmlinux-arm64`)
and a Containerization image store (`store/`) in its base directory, and the peer test boots expect an OCI
archive of the workload at `../oci/peer-arm64.oci.tar`. The quote helper needs `npm ci` in `runner/verify`.
The JS verifier check runs anywhere: `node verify/macrunner.test.mjs`.

Build and run the whole ad-hoc test pass:

```
cd runner && ./build.sh && test/run_tests.sh
```

Both test scripts boot with `--base <run dir>/base`, which symlinks the base directory's kernel and image store
but has its own `volumes/`, so no test can open or lock a live node's ledger.

Individual commands:

```
bin/runner check test/app-compose.json                       # validate, print compose_hash
H=$(bin/runner check test/app-compose.json)
KMS_API_KEY=sk-dummy-... ../.venv/bin/python kms/kms.py --state ../kms-dev --dev-unattested --allow-compose $H &   # DEV-ONLY
bin/runner run --compose test/app-compose.json --app "dev|$H" --out ../runs/x --base .. --kms http://127.0.0.1:8790 --no-attest
# kms.py --record DIR writes every /release response body to DIR/<sha256(clientData)[:16]>-<status>.json
../.venv/bin/python kms/verify_receipts.py ../runs/x --compose test/app-compose.json --dev-unattested
rm -rf ../store/containers/$(cat ../runs/x/container_id.txt)  # the runner keeps the rootfs for inspection
```

## Signed / attested

```
KEYCHAIN=... KEYCHAIN_PW=... SIGN_ID="Apple Development: Name (TEAMID)" PROFILE=... ENTITLEMENTS=... ./sign.sh
test/attested.sh
```

`sign.sh` does a release build, refuses unless `otool -l` shows `minos 27.0` / `sdk 27.0` (App Attest omits the
CDHash extension otherwise), wraps the binary as `build/Runner.app` the way `experiments/mac-vm-approaches/vzattest/build.sh`
does, signs it with `SIGN_ID` using a provisioning profile that grants App Attest, and writes the full
sha256 CDHash to `build/cdhash.txt`.

`test/attested.sh` launches the bundle through `open -n -W` (App Attest needs a LaunchServices launch, so the runner's
exit code is lost and the checks read its output files). It starts `kms.py --allow <cdhash.txt>:<test compose_hash>`
with `/opt/homebrew/bin` first on `PATH` (OpenSSL 3), then checks: a KMS allowlisting another CDHash refuses
(`cdhash_policy_failed`); a changed compose refuses (`cdhash_compose_pair_not_allowed`); the real boot gets the key
and passes the same workload checks as `run_tests.sh`; replaying that boot's `/release` request refuses
(`unknown_or_stale_nonce`); receipts verify with `--cdhash`; the KMSes run with `--record`, the recorded `/release`
bodies contain no key, and the boot's parcel fails to open under a wrong key. The guest's `/attest` response
(`boot/attest.json`, the replay's and `verify_receipts.py`'s source of the attestation now that the runner writes none)
must carry the boot enrollment and verify with `kms/verify_attest.py` (CDHash, compose_hash, data), and must fail under
another CDHash, another compose or other data. Three boots of `app-compose-key*.json` check `/key` stability across
attested boots, a changed compose, and the KMS derivation; a boot of `app-compose-reenroll.json` with
`--reenroll-seconds 5` checks that a later `/attest` serves a new, verifying `mac-compose-enroll/1` key bound to the
boot's receipt_pub. Volume boots check the app-keyed path, the pre-app path for a genesis app, and a boot of
`app-compose-volume2.json` in a non-genesis app `shared` whose `/key` must equal the app derivation. It prints `PASS`/`FAIL` lines and ends with `FAILED=N` (exit code N).

Individual commands (from `runner/`, after `sign.sh`):

```
PATH=/opt/homebrew/bin:$PATH KMS_API_KEY=... ../.venv/bin/python kms/kms.py --state ../kms-state --allow $(cat build/cdhash.txt):<COMPOSE_HASH>   # genesis app
open -n -W --stderr $PWD/../runs/y.txt build/Runner.app --args run --compose $PWD/app-compose.json --app "$(cat build/cdhash.txt)|<COMPOSE_HASH>" --out $PWD/../runs/y --base $PWD/.. --kms http://127.0.0.1:8790 --attest
# verify_receipts.py --cdhash reads ../runs/y/attest.json, a /attest response the guest saved (the runner writes no attestation)
PATH=/opt/homebrew/bin:$PATH ../.venv/bin/python kms/verify_receipts.py ../runs/y --compose app-compose.json --cdhash $(cat build/cdhash.txt)
```

The verifier calls `openssl verify -no-CAstore`, which macOS's `/usr/bin/openssl` (LibreSSL 3.3.6) does not
support; use Homebrew OpenSSL 3.

## DEV-ONLY paths

`runner run --no-attest`, `kms.py --dev-unattested` and `verify_receipts.py --dev-unattested` release
the key and accept receipts with nothing binding them to a measured binary. They exist so the
ad-hoc build can be tested. Never point them at a real key.

`runner run --dev-test-anchor CA.der` adds one DER certificate to the pinned upstream anchors, so the metering
test can reach `test/fake_upstream.py`. The runner refuses it together with `--attest`.

`runner run --dev-task-boot-delay-ms N` holds each task boot N ms before its receipt chain exists, the window a slow
App Attest assertion opens in a signed run; `run_tests.sh` uses 3000 to attach while a task is booting. Refused with
`--attest`.

`kms.py --dev-omit-app-key` (needs `--dev-unattested`) exists only for the parcel-refusal test. `test/near_diversity.sh
--no-attest` runs through the dev KMS; use `--attest` with a real NEAR key.
