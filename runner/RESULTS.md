# runner results, 2026-10-08 (ad-hoc build, unattested)

Question: can one Swift binary take a dstack `app-compose.json`, boot it in a VM whose only egress
is the binary's own proxy, keep the API key out of the guest, pin upstream TLS, cap spend, and
sign per-exchange receipts bound to the compose hash? Everything except App Attest itself was run
for real. The attestation step is written and fails loudly on this build, as intended.

Result: 34 of 34 checks pass (`evidence/20261008T143938/test.log`). A later ad-hoc pass with encrypted key release
and usage metering passes 52 of 52 (`evidence/20261008T150144/test.log`; section below).

## Conditions

- Mac mini M4 Pro, macOS 27.0 (26A428), Xcode 27.0 (27A266a), Swift 6.4. SIP on, nothing changed.
- Containerization 0.33.4 (SwiftPM, statically linked), swift-nio 2.104.0, swift-nio-extras 1.35.1.
- Kernel: the spike's Kata 3.17.0 `vmlinux-arm64` (6.12.28), sha256 `67bac9f4…6af6ea0`, compiled into the binary and checked before boot.
- Initfs: `ghcr.io/apple/containerization/vminit@sha256:4551a462…2e33e98af` (tag 0.33.4), rebuilt per boot.
- Guest image: `docker.io/curlimages/curl@sha256:c1fe1679…f9f9a69` (curl 8.11.1 on Alpine). Plain alpine
  has no client that can speak HTTP over a unix socket (busybox wget cannot), and the guest has no network
  to `apk add curl`, so the workload is Alpine with curl preinstalled.
- Build: ad-hoc, hardened runtime, entitlement `com.apple.security.virtualization` only.
  CDHash (full sha256) `1a3edbb20edb18fb3a36f9f78c96a8c2fa1c00b044cd387e4c326fa1185a11de`, flags `0x10002(adhoc,runtime)`.
  `otool -L`: only `/System/Library/Frameworks` and `/usr/lib` (`evidence/.../build.log`).
- Stand-in KMS on 127.0.0.1, Python 3.9.6 + cryptography 50.0.2 in `~/vz-runner/.venv`.
- Upstream: real `https://httpbin.org` (echoes request headers); dummy key `sk-dummy-<32 random hex>`, fresh per pass, never written to disk by the test.
- Test compose: written by dstack's own SDK serializer (`to_deterministic_json`), compose_hash `13b39fee98700003fee078da5573738a737fd20e681305c01b09989ef0b33da8`.

## Steps

Evidence paths are under `evidence/20261008T143938/`.

| Check | Result | Evidence |
|---|---|---|
| `runner check` hash equals dstack SDK `get_compose_hash` on the same bytes | PASS, both `13b39fee…` | `test.log`; `test/app-compose.sdk-hash` |
| One changed byte (`runner-test` → `runner-tesT`) changes the hash | PASS | `test.log` |
| Tag-only image refused | PASS: `image "docker.io/curlimages/curl:8.11.1" is not pinned by an @sha256: digest` | `tag.txt` |
| `--attest` on the ad-hoc build | Fails loudly as designed: `DCAppAttestService.isSupported is false. This is not a signed, App Attest-entitled build…` | `attest.txt` |
| Attested-mode KMS gets an unattested request | Refused: `KMS /release -> 403: {"error": "attested_request_required"}` | `devreq.txt` |
| Dev KMS gets a compose hash not on its list | Refused: `compose_hash_not_allowed` | `notallowed.txt` |
| VM boots with no NIC | PASS: `ls /sys/class/net` = `lo`; `ip addr` shows only `lo` (127.0.0.1, ::1) | `boot/guest_stdout.txt` `== net` |
| Direct fetch by IP | Fails: `curl: (7) Failed to connect to 1.1.1.1 port 443 after 0 ms` | `== direct_ip` |
| Direct fetch by name | Fails: `curl: (28) Resolving timed out after 5001 milliseconds` | `== direct_dns` |
| Allowlisted GET through the proxy | 200 from httpbin | `== allowed` |
| Key injected and seen upstream | httpbin echoed `"Authorization": "Bearer [REDACTED-API-KEY]"`. The marker replaces an exact byte match of the key, so httpbin received the key; the runner logged `redacted API key reflected by httpbin.org/anything/allowed` | `== allowed`, `runner.log` |
| Guest's own `Authorization: Bearer GUEST-SECRET` and `x-api-key: guest-xkey` | Stripped; neither string appears upstream | `== allowed` |
| Anthropic-style `x-api-key` injection on the metered rule | `"X-Api-Key": "[REDACTED-API-KEY]"` upstream, 200 | `== metered_ok` |
| Host not allowlisted (`example.org`) | 403 `not allowlisted: GET example.org/` | `== not_allowlisted_host` |
| Wrong method (DELETE), wrong path (`/get`) | 403 each | `== wrong_method`, `== wrong_path` |
| Dot segments (`/anything/../get`, sent with `--path-as-is`) | 403 `dot segments refused` | `== dot_segments` |
| `max_tokens` 5000 against remaining budget 900 | 402, refused before any upstream byte | `== metered_over_budget` |
| Metered rule, no `max_tokens` | 400 | `== metered_no_max_tokens` |
| Redirect | 302 returned to the guest, not followed | `== redirect_not_followed` |
| TLS pin: `example.com` is allowlisted but chains to SSL.com TLS ECC Root CA 2022 | 502. Runner log: `TLS pin refused example.com: … Code=-67843 "Certificate 3 "SSL.com TLS ECC Root CA 2022" has errors: Root is not trusted"`. That root is in `/System/Library/Keychains/SystemRootCertificates.keychain` and host `curl https://example.com/` gets 200 with `ssl_verify_result=0`, so the refusal comes from the pinned anchor set | `== pin_fail`, `runner.log` |
| Per-boot request cap (8) | Requests 9 and 10 get 429 | `== request_cap` |
| Key absent from the guest rootfs ext4 | 0 matches for the key. Positive control: the guest saved the echoed response to `/home/curl_user/upstream.json`, and `Bearer [REDACTED-API-KEY]` is found in the same ext4 image | `test.log` |
| Key absent from initfs, guest stdout, receipts, runner log | 0 matches | `test.log` |
| Receipts verify (signature under `receipt_pub` from clientData, seq, prev chain, compose_hash) | PASS, 7 receipts. The 8 requests charged against the cap include the pin-failed one, which made no exchange and so has no receipt | `verify.txt`, `boot/receipts.jsonl` |
| One byte changed in receipt 2 (`"status":200` → `201`) | Fails: `bad_signature seq=2` | `tamper-sig.txt` |
| Receipt 3 deleted | Fails: `seq_gap expected=3 got=4` | `tamper-drop.txt` |

## Found along the way

- **vminit 0.26.5 (the spike's initfs) cannot relay a socket into a container under Containerization 0.33.4.** The
  first boot failed with `vmexec error: mount failed with errno 20: failed initial mount source=/run/sockets/<id>.sock
  target=…/rootfs/run/egress.sock type=bind`. The 0.33.4 library stages relayed sockets under `/run/sockets/`
  and bind-mounts them in, and the older vmexec makes the mount target a directory. Using the version-matched
  `vminit:0.33.4` fixed it.
- **`ContainerManager(initfsReference:)` reuses any existing `store/initfs.ext4` regardless of the reference.**
  Changing the reference to 0.33.4 would have kept booting the 0.26.5 initfs without saying so. The runner
  now builds the initfs from the digest-pinned image into the run directory on every boot and passes it as a `Mount`.

## Still unattested, pending the signed build

- **App Attest.** `--attest` code path (`generateKey`, `attestKey` over `sha256(clientData)`, send to the KMS) is written
  and not run; the ad-hoc binary reports `isSupported == false`. The signed build needs the dsmack keychain unlocked
  (same blocker as `experiments/mac-vm-approaches/vzattest/RESULTS.md`), the bundle shape from `experiments/mac-vm-approaches/vzattest/build.sh`
  with `runner` as the executable, and the open AMFI question of the VZ entitlement on a profile-signed app.
- **KMS attested branch.** `kms.py --allow CDHASH:COMPOSE_HASH` runs `verifier/core.verify_attestation` with the
  app/macos policy (pinned Apple root, production AAGUID, category 3, Mac ACL, CDHash allowlist), then checks the
  (CDHash, compose_hash) pair and the nonce. Only its refusal of an unattested request was exercised. It needs
  OpenSSL 3 on `PATH` (the mini's `/usr/bin/openssl` is LibreSSL 3.3.6 and lacks `-no-CAstore`).
- **Receipt binding.** In this pass `receipt_pub` is bound to nothing: `verify_receipts.py --dev-unattested` proves the
  chain is internally consistent and matches the compose, not that a measured runner signed it. `--cdhash` verifies
  `attestation.cbor` over the same clientData once one exists. No checkpoint assertions and no leaf-expiry handling yet.

## Signed/attested: PASSED 2026-10-08 (`FAILED=0`)

Signed `Runner.app` (Apple Development, team DC9JH5DRMY, minos/sdk 27.0), full CDHash
`d2a0b9295a6d1583c1759b3b461f5842d96c83fdcdde9a4b15daaa5a9bb6e5ce`. Evidence (disk images excluded):
`evidence/attested-20261008T145504/`.

| Check | Result |
|---|---|
| compose hash equals dstack SDK | PASS |
| KMS with a different CDHash allowlisted | 403 `cdhash_policy_failed` |
| changed compose | 403 `cdhash_compose_pair_not_allowed` |
| attested boot | key released, logged `attested` |
| replay of the boot's `/release` | 403 `unknown_or_stale_nonce`; key released exactly once |
| workload checks (only `lo`, direct IP/DNS fail, allowlist, auth strip, key injection, cap, pin) | all PASS |
| key absent from rootfs, initfs, out dir, KMS logs | PASS (rootfs positive control finds marker) |
| 7 receipts verify, boot binding `attested, cdhash d2a0b929…` | PASS; tamper and drop rejected |

Pre-run checks done without the password:

- Release build: `otool -l` shows `minos 27.0`, `sdk 27.0`; `sign.sh`'s check on that passes.
- `sign.sh` with the identity swapped for an ad-hoc signature, the profile dropped and `entitlements.plist` (VZ only):
  bundle layout, `codesign --verify --strict`, and `build/cdhash.txt` written from `CandidateCDHashFull`.
- `test/attested.sh` against that ad-hoc bundle, end to end through `open`, both KMSes, and the replay request.
  Every attested release was refused with `wrong_app_id`, so the positive checks failed as expected (`FAILED=29`).
- An ad-hoc-signed bundle launched through LaunchServices does App Attest: `isSupported` was true and
  `attestKey` returned a production attestation chaining to the Apple root. The RP ID is `sha256("dev.dsmack.provider")`
  (no team prefix), validation category 8, and no CDHash extension. The KMS refuses it at the app ID check
  (`DC9JH5DRMY.dev.dsmack.provider` required); the category (3) and CDHash checks would refuse it too.
  The same binary run directly (`bin/runner`) still reports `isSupported == false`.
- `test/run_tests.sh` after moving the workload checks into `test/boot_checks.sh`: 34 of 34 pass.

## Encrypted key release and usage metering: ad-hoc pass 2026-10-08, `FAILED=0`

Same conditions as above except: ad-hoc CDHash `b1e9c34729c49532ef6df65b1d9b0a29a37354f955faf1380e626682a492cfb3`;
test compose regenerated (new hash `d1f6cda1…13fabe4e`, `max_requests` 9, a GET rule that injects `x-api-key`, the
metered httpbin call renamed `metered_no_usage`); a second compose `test/app-compose-meter.json` (`687ec201…11fa95`)
for the metering boot. 52 of 52 checks pass. Evidence: `evidence/20261008T150144/` (ext4 images and the fake
upstream's TLS private key excluded). The signed suite has not been rerun since these changes.

Key release. The runner makes a second P-256 key in RAM and puts its public key in clientData as `eph_pub`, next to
`receipt_pub`, so the attestation covers it. `/release` now returns `{"epk", "sealed"}`: ECDH between a one-time KMS
key and `eph_pub`, HKDF-SHA256 (info `mac-compose-key-release/1`), AES-256-GCM with AAD `sha256(clientData)`. Both
KMS modes return only this. `kms.py --record DIR` writes each `/release` response body, as sent, to
`DIR/<sha256(clientData)[:16]>-<status>.json`.

| Check | Result | Evidence |
|---|---|---|
| Boot's `/release` body recorded | `{"epk": "BMid…", "sealed": "Pvtv…"}`, 69 sealed bytes (12 nonce + 41 key + 16 tag) | `kms-bodies/8f00e03d95b0ca47-200.json` (name = `boot/clientData.bin` hash) |
| Key in any recorded body (dev KMS: 2 releases, 1 refusal; attested-mode KMS: 1 refusal) | 0 hits | `test.log` |
| Open the boot's parcel with a fresh P-256 key | `InvalidTag` | `wrong-key.txt` |
| Runner decrypted with its own key | key reached httpbin (`Bearer [REDACTED-API-KEY]` echoed), all workload checks pass | `boot/guest_stdout.txt` |
| Key in out dir, runner logs, rootfs, initfs | 0 hits (unchanged checks) | `test.log` |

Metering. The `max_tokens` pre-check stays as a reservation. On a `"metered": true` rule the proxy reads the
upstream JSON's `usage`: `total_tokens` if present (OpenAI), else `input_tokens + output_tokens` (Anthropic), and
settles the budget by `usage − reservation`. A metered response without usage is refused to the guest with 502, and the
reservation stays charged. Metered receipts carry `tokens_reserved` and `tokens_charged`.

Testing it needs an upstream that returns `usage`; httpbin cannot, and a real provider needs a real key. The test runs
`test/fake_upstream.py` on `https://localhost:8443` under a CA it generates per run, and the runner trusts that CA only
with `--dev-test-anchor CA.der`, which the runner refuses together with `--attest`. Policy hosts may now carry an
explicit port (`localhost:8443`), matched exactly against the guest's `Host`. The fake answers 401 unless the runner
injected the test key, so a 200 also shows the key was injected.

| Check | Result | Evidence |
|---|---|---|
| `--attest --dev-test-anchor` | refused: `--dev-test-anchor is DEV-ONLY and refused with --attest` | `attest-anchor.txt` |
| Anthropic usage, reserve 100 | 200, receipt `tokens_reserved 100, tokens_charged 65` (25 + 40) | `meter/guest_stdout.txt`, `meter/receipts.jsonl` |
| OpenAI usage, reserve 200 | 200, receipt `tokens_charged 150` (`total_tokens`) | same |
| Response without usage, reserve 100 | 502 `metered upstream 200 response has no usage; reservation of 100 stays charged` | `== no_usage`, `meter.log` |
| Reserve 685 | 200. Remaining was 1000 − 65 − 150 − 100 = 685; without settling it would be 600 and this would be 402 | `== settled` |
| Reserve 621 | 402 `max_tokens 621 exceeds remaining per-boot budget 620` (685 − 65) | `== exhausted` |
| Metering receipts verify | 3 receipts | `verify-meter.txt` |
| Real upstream, no usage (httpbin, main boot) | 502 `has no usage`; the next 5000-token request reports remaining `900`, so the 100 stayed charged | `boot/guest_stdout.txt` `== metered_no_usage`, `== metered_over_budget` |

`test/attested.sh` now starts both KMSes with `--record`, sets `KMSREC` for `boot_checks.sh`, and greps the
wrong-CDHash KMS's recorded bodies for the key; through `boot_checks.sh` it gets the parcel, wrong-key, `xkey` and
no-usage checks. The metering boot is ad-hoc only, because its anchor flag is refused in attested mode.

## Abalone node interface: ad-hoc pass 2026-10-08, `FAILED=0`

Spec: `notes/abalone-node-interface.md`. Ad-hoc CDHash (truncated, from `build.log`) `acfa5bcd7a6a02e80cebffd383d9b21793c9815c`.
97 of 97 checks pass. Evidence: `evidence/20261008T153752/` (ext4 images, KMS master keys and the synthetic keys file
excluded; `test.log` has every PASS line). The signed suite (`test/attested.sh`) was rewritten for this and has not been run.

Eight boots: the main workload, metering, the abalone-interface compose (provider quotes), the abalone peer image from
an OCI archive, a CONNECT boot from that peer image, and three `/key` boots. The KMS read its API key from a synthetic
abalone key store (`keys.json` in the run dir, lib/nodekeys.mjs format) in every boot.

| Check | Result | Evidence |
|---|---|---|
| `/key`: same path twice in a boot | same 64-hex key | `boot/guest_stdout.txt` `== key_a`, `== key_a2` |
| `/key`: value equals HKDF(HKDF(master, app-key info), get-key info) recomputed from `master.key` | PASS | `test/derive_key.py`, `test.log` |
| `/key`: same compose, two boots, KMS restarted on the same `--state` between them | same key | `key1/`, `key2/guest_stdout.txt` |
| `/key`: changed compose (`app-compose-key2.json`) | different key | `key3/guest_stdout.txt` |
| KMS parcel without `app_key` (`kms.py --dev-omit-app-key`) | runner refuses: `KMS parcel must be {"api_key": str, "app_key": 64 hex}, got keys ["api_key"]` | `noappkey.txt` |
| `master.key` mode | 0600 | `test.log` |
| `--keys-file` missing file / provider without `active` label / missing label | KMS exits: `FileNotFoundError` / `KeyError: 'nearai'` / `0 keys for provider redpill label nope`; neither key value in any KMS log | `kms-no*.log` |
| `/attest` in `--no-attest` | `{"type":"dev",…}`; `assertClientData` is exactly `{"compose_hash":"…","data":"abalone-attest/1\|peerA\|peerB\|n1","domain":"mac-compose-assert/1"}` | `assert-client-data.txt` |
| CONNECT to the one `egress.tcp` entry (127.0.0.1:8794), from node in the peer image | `HTTP/1.1 200 Connection Established`, then the host server's file through the tunnel | `tunnel/guest_stdout.txt`, `tunnel-server.log` |
| CONNECT to an unlisted port / unlisted host | `HTTP/1.1 403 Forbidden`, logged | `tunnel/guest_stdout.txt`, `tunnel.log` |
| `--oci-archive` with the abalone peer archive (manifest `sha256:4de0c490…`) | loaded, tagged as the compose image, boots; `node -e console.log(process.version)` prints `v22.23.3` | `peer.log`, `peer/guest_stdout.txt` |
| `--oci-archive` with a compose naming another digest | refused before boot: `manifest digest sha256:4de0c490… != compose image digest sha256:4de0c491…` | `peer-mismatch.txt` |
| Quote helper with one byte appended | refused before boot: `sha256 … != compiled-in f6ee27d3…` | `tampered-helper.txt` |
| `/provider-quote?host=api.redpill.ai` before any request | 404 | `abalone/guest_stdout.txt` |
| GET `api.redpill.ai/v1/models`, rule `provider_quote` redpill with the measured gateway compose `0637b3d5…` | live quote verified (Intel PCS, TCB UpToDate, ACI report_data for our nonce, RTMR3 replay, compose accepted), SPKI pin `e52fdca5…` matched, 200 | `abalone.log`, `abalone/provider-quote-*.json` |
| Second request to the same host | 200, no second fetch | `abalone.log` |
| `provider_quote_sha256` | in both receipts; equals sha256 of `/provider-quote` bytes the guest read and of the saved report | `abalone/receipts.jsonl`, `== redpill_quote_bytes` |
| `tee.redpill.ai` rule accepting only compose `00…00` | 502 `measured compose-hash 0637b3d5… is not in the accepted list`; `/provider-quote` for it 502 | `== wrong_compose` |
| Rule whose `attestation_url` replays a real RedPill report fetched earlier (stale nonce), upstream `localhost:8443` | 502 `report_data: report … != recomputed …`; the fake upstream saw no request | `== replayed`, `fake.log` |
| `openrouter.phala.com`: quote verifies (keyset attests SPKI `1989293e…`), host serves `f1a8a26d…` | TLS refused, 502, logged `attested SPKI pin refused` | `== spki_mismatch`, `abalone.log` |
| `nearai` with the dummy key | 502 `…/v1/attestation/report answered HTTP 401`; no upstream contact | `== nearai_bad_key` |
| Key in abalone/meter out dirs, KMS logs, KMS bodies, rootfs, initfs | 0 hits | `test.log` |

The redpill and phala kinds were checked against their live endpoints only (api.redpill.ai, tee.redpill.ai,
inference.phala.com serve the same gateway keyset). The nearai kind has never verified a real report: NEAR's
report endpoint answers 401 without a valid key, and no captured NEAR report was available to test against. `test/near_diversity.sh N KEYS_FILE --attest` is for the first live run; with the
synthetic key it fetched 3 times through the runner and got 3 `invalid_api_key` answers, so injection works.

`verify/macrunner.mjs` (laptop, `node verify/macrunner.test.mjs`): against the 14:55 signed boot in
`evidence/attested-20261008T145504/` it accepts the real attestation and then refuses on the missing `enrolled_at`
(that capture predates it); it refuses dev evidence, another CDHash, another compose, and a tampered clientData.
`kms/verify_attest.py` with the same capture passes the attestation and refuses on the compose (the test compose has
changed since). Neither has seen a real assertion yet; `test/attested.sh` produces one.

## Named volumes: ad-hoc pass 2026-10-08, `FAILED=0`

Ad-hoc CDHash (truncated) `cefc514afc27097dfcbbb9f1f2b85a7a01d05699`. 108 of 108 checks pass. Evidence:
`evidence/20261008T160103/` (ext4 images excluded). The signed suite gained three checks (`attested_volume_persists`,
`attested_volume_keyed_by_cdhash`, `attested_volume_marker_is_compose_hash`) and has not been run.

Three boots of the abalone peer image with `/bin/sh` as `command`: each prints the ledger file, lists the volume,
prints its `/proc/mounts` line and `.abalone-persistent`, and appends 8 random bytes in hex.

| Check | Result | Evidence |
|---|---|---|
| `runner check` on `"/tmp/ledger:/abalone-ledger"` | refused: `is not <name>:/<path> (only named volumes; host binds and options are refused)` | `volume-bind.txt` |
| First boot of `app-compose-volume.json` | image created at `~/vz-runner/volumes/dev/537fc897…/ledger.ext4`; volume holds only `.abalone-persistent` and `lost+found`; mounted `/dev/vdc /abalone-ledger ext4 rw` | `vol1.log`, `vol1/guest_stdout.txt` |
| `.abalone-persistent` | equals the boot's compose_hash (`537fc897…` and `a2764a55…` in the two composes) | `== marker` |
| Second boot, same compose | reads the first boot's token (`54876aebb701903c`); no image created | `vol2/guest_stdout.txt`, `vol2.log` |
| Boot of `app-compose-volume2.json` (name field differs) | new image under `volumes/dev/a2764a55…/`, volume holds only the marker and `lost+found` | `vol3.log`, `vol3/guest_stdout.txt` |
| `--attest` on the ad-hoc build (fails later at `isSupported`) | logs `volumes keyed by cdhash cefc514a…5ecc4f`, equal to `codesign -d` `CandidateCDHashFull sha256` of `bin/runner`, so attested volumes land under `volumes/<cdhash>/`, apart from `volumes/dev/` | `attest.txt` |

Also checked by hand: `ledger:/x:ro`, `./x:/x`, an undeclared name, an extra top-level name, and a declaration with
`driver` are each refused by `runner check`.

## NEAR admission from Base DstackApps: ad-hoc pass 2026-10-08, `FAILED=0`

Ad-hoc CDHash (truncated) `311bda264cfc5e2b4a2d8ac4a1e3ec7fe2066f25`, helper sha256 `860b0e0a…`. 128 of 128 checks
pass. Evidence: `evidence/20261008T182458/` (`test.log`, `provider-quote-unit.txt`, the abalone boot). The NEAR rule in
`test/app-compose-abalone.json` and the abalone peer compose now carry `onchain` (rpc `https://mainnet.base.org`,
apps `0xf550fdfb…` gateway and `0x2c0a0c96…` models) instead of `compose_hashes`. The signed suite needs no change
(it has no provider quote rule) and has not been run.

The unit check runs `admit` on the gateway and first model attestation recorded in
`evidence/node-20261008T170947/` (trimmed copy: `test/near-report-20261008.json`); with no API key it cannot check
the quote or nonce, only measurement and admission.

| Check | Result |
|---|---|
| Hardcoded selector vs the helper's keccak256 of `allowedComposeHashes(bytes32)` | `0x2f6622e5`, equal to `cast sig` |
| `eth_blockNumber` through the anchors | block 52359806 (laptop), 52359876 (mini) |
| Gateway compose `8bc802c9…` on `0xf550…`; model compose `c82b1a2e…` on `0x2c0a…` | true, true |
| Random compose `11…11` on `0xf550…` | false |
| Recorded gateway / model attestation, apps both | admitted by `0xf550…` (compose `8bc802c9…`) / `0x2c0a…` (compose `55db164f…`) |
| Recorded gateway, apps `[0x2c0a…]` only | refused: `measured app-id 0xf550… is not in onchain.apps` |
| Recorded model at block 51000000 (before `55db164f…` was added) | refused: `not allowed by DstackApp 0x2c0a… at block 51000000` |
| app-id event payload swapped to `2c0a…`, digest kept | refused: `app-id event payload does not match its digest` |
| `eth_call` on a non-contract address (result `0x`) | refused |
| `eth_call` at a block past the head | refused: `RPC eth_call: {"code":-32001,"message":"block not found: …"}` |
| Anchors = Amazon Root CA 1 only | refused: `unable to get local issuer certificate` |
| `http://` rpc | refused: `is not https` |
| `runner check`: rule with both `compose_hashes` and `onchain`; an app address with uppercase | refused |
| `nearai` with the dummy key (helper reads the block first) | 502 `HTTP 401`, so the pinned RPC leg passed in the runner |
| redpill (static `compose_hashes`) with the new compose-hash payload/digest check | verified live, as before |

Not exercised: a NEAR boot with a real key, so `onchain` in a receipt and in `verify_receipts.py` has not been seen.

## Task guests: ad-hoc pass 2026-10-09, `FAILED=0`

Spec: `notes/abalone-node-interface.md` item 8. Ad-hoc CDHash (truncated) `33eed49dafdf5ce11f78b112d09e0d82ab5ad438`.
184 of 184 checks pass, 55 of them new (superseded: see the next section). Evidence: `evidence/20261008T205959/` (`test.log`, `tasks/guest_stdout.txt`,
`tasks.log`, `task-collect*/`, `verify-task*.txt`, `tasks-real/`; ext4 images excluded). `test/attested.sh` now runs the
same task boot under App Attest and has not been run.

Two peer boots from the abalone peer image, each driving the task API from node inside the peer VM. The first starts
seven tasks of the test image (`test/task-image/`, alpine + a shell NDJSON echo, `sha256:b286d55d…`); the second boots
the real abalone task image (`sha256:830b9921…`, `bin/task-guest.mjs`) once.

| Check | Result | Evidence |
|---|---|---|
| `/task/start`, then the same body again | the same `{compose_hash, state:"booting", task_id}`; one `task … running` log line | `== start`, `== start_again`, `tasks.log` |
| Same task_id, other compose (another `abalone.auth_hash`) | 409 `was started with compose …` | `== start_other_compose` |
| Image not in `tasks.images` / non-empty egress / unknown resource | 403 each, before anything is booted | `== start_image_not_admitted`, `== start_egress`, `== start_unknown_resource` |
| 2 MiB body to `/task/stop` | 413 `body over 1 MiB` (only `/task/start` gets 28 MiB) | `== stop_body_over_1mib` |
| `tasks.resources.small.max_seconds` 3600 | `runner check` refuses | `tasks-overcap.txt` |
| `--task-archive` with the peer archive / on a compose without tasks | refused before boot | `task-archive-wrong.txt`, `task-archive-notasks.txt` |
| Attach, then a second attach | 200, then 409 | `== attach`, `== attach_second` |
| `{"ready":true}` printed before the first attach | delivered on attach | `== ready_buffered` |
| NDJSON echo | round trip | `== echo` |
| Detach right after `{"op":"later"}`, reattach 4 s later | both delayed lines delivered | `== later_delivered` |
| 5 MiB + newline printed while detached | `dropped_bytes` 1048577; the reattach gets exactly 4194304 bytes, the newest (x… then the newline) | `== dropped`, `== flood_bytes` |
| `{"op":"exit"}` | `{"done":true}` arrives, then the runner closes the stream; status exited, exit_code 0, wall 14 s | `== done`, `== closed_on_exit`, `== exited` |
| `/task/collect` twice | 200, 200, identical sha256 | `== collect` |
| Attach after exit | 409 | `== attach_after_exit` |
| Third task with two running | 429 | `== start_over_max` |
| `/task/delete` or `/task/collect` on a running task | 409 | `== delete_running`, `== collect_running` |
| `/task/stop` grace 1 s, then again | stopped, reason stop, exit 137 (the shell ignored SIGTERM; SIGKILL after the grace); the repeat returns the same status | `== t2_stopped`, `== stop_t2_again` |
| Resource `capped` (test-only menu entry, 3 s) | stopped, reason time_cap, wall 9 s (3 s cap + 5 s grace + VM stop); its `exit` receipt says time_cap | `== t5_time_cap`, `verify-task-t5.txt` |
| Delete, then status | 200, then 404; task container roots gone | `== delete_t1`, `== status_deleted` |
| A task still running when the peer exits | stopped, reason runner_exit | `tasks.log` |
| `out/net.txt` (`ls /sys/class/net` in the task VM) | `lo` only | `task-collect/out/net.txt` |
| `/in` | readable (`hello from inputs`); `touch /in/x` fails `Read-only file system` | `task-collect/out/` |
| `/out` read host-side: nested dir, a 136-byte path (ustar prefix split), an executable file | in the collect tar as written; the exec bit kept | `task-collect.tar` |
| `verify_receipts.py --task --dev-unattested` on the extracted collect | ok: events task-start, (attach, detach)×3, exit; `inputs_sha256` equals the driver's sha256 of the tar; Python's rebuilt out tar has the receipt's `out_sha256` | `verify-task.txt` |
| One byte changed in `out/result.json` / an extra file in `out/` / changed `guest/app-compose.json` / another peer compose | `out_sha256_mismatch` / `out_sha256_mismatch` / `compose_hash_mismatch` / `peer_compose_hash_mismatch` | `verify-task-*.txt` |
| Real task image: start, attach, `init` (prompt, model, tools [read], check `git --version && cat hello.txt`), `finish` | Pi started and sent its model request (`{"t":"infer","id":1,…}`, left unanswered); `{"t":"outputs",…}`; exited 0, wall 6 s; `out/test.log` shows git 2.54.0 and the input; `finish.json` `{"reason":"runner test"}`; receipts verify | `tasks-real/guest_stdout.txt`, `real-collect/`, `verify-real.txt` |

## Signed task pass failure and fix, 2026-10-09: ad-hoc `FAILED=0`

The first signed run of `test/attested.sh` with tasks failed 41 task checks (`~/vz-runner/last-attested.log`,
`runs/attested-20261008T210745/`). The peer driver stopped after `== start_unknown_resource`, while its next request
(a 2 MiB body, expecting 413) was in flight. That request never reached the runner. The unified log shows how the
runner ended: `exited due to SIGPIPE | sent by runner`, 120 s after the stall, which is the proxy's idle timeout.

Reproduced ad-hoc with a stress compose (`test/relay_stress.py`): 2 MiB uploads back to back while task VMs boot.
- One round died with exit 141 (SIGPIPE) on its second upload.
- With SIGPIPE ignored, about one round in two stalls: an upload times out, and so does the `/attest` after it.
- A connection log added for one round (removed after) showed the stalled connection. It was accepted on the host as
  the task VM started and delivered 0 bytes. Two later connections were accepted but delivered nothing either. When
  the idle handler closed the first one 120 s later, the queued requests went through.
- vminitd's `VsockProxy` in the peer VM serves every relayed connection from one epoll supervisor and connects to the
  host vsock with a blocking `connect`. That fits one stuck connection blocking the rest. The bug that leaves the first
  connection with no bytes is in Containerization/VZ and is not found or fixed.
- Two probes ruled out the host relay's dispatch sources: on this Mac a resumed read source refires on unread data, and
  a write source on a full AF_UNIX socket fires once the peer drains it.
- The SIGPIPE comes from `BidirectionalRelay` writing with `write(2)` to the host socket after NIO closed it.

Fixes:
- **SIGPIPE.** `signal(SIGPIPE, SIG_IGN)` at startup; the relay gets EPIPE and tears that connection down.
- **Stall.** A connection that sends no request head within 10 s is closed (`Proxy.swift`, `firstHead`). With the fix,
  a stress round that stalled got its 413 after 10021 ms, on the driver's retry, and every request after it was
  normal. The test driver retries a request whose connection closes before any response (at most 3 times) and
  prints the count (`== retries`; 0 in this pass).
- **Domain** (contract owner's point). The task boot clientData domain is now `mac-compose-task-boot/1`. Before, a
  verifier that took an `/attest` response (`mac-compose-assert/1`, data chosen by the peer) as the binding would have
  accepted any receipt key the peer named. `verify_receipts.py --task` requires the new domain.

New checks, all PASS in `evidence/20261008T214329/` (190 of 190):
- `task_silent_connection_closed_runner_survives`, `task_silent_connection_close_logged`: a raw connection silent for
  11 s is closed, 1 MiB written into it afterwards does no harm, and `/attest` then answers 200.
- `task_peer_traffic_during_task_boots`: 2 MiB uploads and `/attest` calls back to back while two task VMs boot, all answered.
- `task_boot_domain`.
- `task_attest_shaped_binding_refused`: `attest.json` carries an `/attest` wrapper of the real clientData;
  `task_binding_not_task_boot_domain`.
- `task_attest_shaped_clientdata_refused`: `clientData.bin` replaced by the wrapper; `wrong_boot_domain mac-compose-assert/1`.

Not shown: two control runs of the task boot built without the SIGPIPE line survived, so no ad-hoc check fails without
that fix; the evidence for it is the signed run's log and the one stress round. The stall itself is not in
`run_tests.sh` because it is intermittent; the overlap check passes whether or not a stall happens, as long as the retry
succeeds. App Attest timing (an assertion per task boot) is the plausible reason the signed run hit the stall on its
first upload, when the ad-hoc passes did not; not confirmed.

## Attach while booting: ad-hoc pass 2026-10-09, `FAILED=0`

A live paid run attached to a task while its boot was waiting on the App Attest assertion, before the task's receipt
chain existed, and `chain!.sign` in `TaskRun.activate` crashed the runner (SIGTRAP). The coordinator fixed it
(`pendingAttach`: an attach or detach with no chain signs nothing, and boot signs a pending attach right after
task-start). The regression test holds the boot with `--dev-task-boot-delay-ms 3000`, then attaches, writes stdin and
closes (a detach before the chain exists), attaches again, writes stdin and exits the task. 197 of 197 checks pass
(`evidence/20261009T013234/`): `task_early_attach_200`, `task_early_reattach_200`, `task_early_attaches_while_booting`,
`task_early_stdin_delivered` (both lines echoed), `task_early_exited_0`,
`task_early_attach_receipts_after_task_start` (events task-start, attach, detach, exit; the closed first attachment
leaves no receipt), `task_boot_delay_refused_with_attest`. Control: the same boot built with `chain!.sign` restored
ended at `== start_early` with exit 133 (SIGTRAP).

## Keys and volumes by app id, volume lock, durability: ad-hoc pass 2026-10-09, `FAILED=0`

Design v2 of `notes/succession-design.md`. Ad-hoc CDHash (truncated) `0f7019d4b840fc56fe0c4c07c668e88a35c52fb5`.
225 of 225 checks pass. Evidence: `evidence/20261009T075641/` (ext4 images excluded; `run_tests.log` is the console).
Every boot used `--base <run>/base`, which links `~/vz-runner`'s kernel and store but has its own `volumes/`; the live
node (`runs/node-20261009T072011`, KMS on 8820) kept running through all three passes.

| Check | Result |
|---|---|
| `kms_build_in_two_apps_fails`, `kms_dev_mode_refuses_real_cdhash` | a build under two apps, or a real cdhash in dev mode: the KMS refuses to start |
| `runner_requires_app` | no `--app`: `missing --app <value>` |
| `app_kms_refuses_build_not_in_allowlist` | HV under app `shared`, not admitted: 403 `compose_hash_not_allowed` |
| `app_kms_refuses_build_under_other_app` | HV2 asking for app `other` while admitted to `shared`: 403 `build_not_in_requested_app` |
| `parcel_without_app_key_refused` | parcel without `app_key` refused (message now lists `app`) |
| `genesis_app_key_matches_pre_app_derivation`, `get_key_matches_kms_derivation` | genesis app `dev|<compose>` gives the `/key` that `test/derive_key.py` computes the old way (`"…/1|" + cdhash + "|" + compose`) |
| `volume_created_on_first_boot_under_app_dir` | image at `volumes/<sha256("dev|HV")>/ledger.ext4` |
| `legacy_volume_path_used_for_genesis_app`, `legacy_volume_not_recreated`, `legacy_volume_holds_earlier_tokens` | image moved to `volumes/dev/<HV>/`: the next boot of HV mounts it there, nothing created, both earlier tokens read |
| `genesis_upgrade_uses_legacy_path`, `genesis_upgrade_reads_ledger`, `genesis_upgrade_keeps_key` | HV2 admitted to app `dev|HV` (an upgrade of a pre-app build): same legacy image, all three earlier tokens, same `/key` as HV |
| `app_volume_lock_refuses_second_boot`, `app_locked_boot_started_no_guest` | HVH (app `shared`) holding for 20 s; HV2 in `shared` meanwhile: `volume ledger at …/ledger.ext4 is locked (Resource temporarily unavailable): another runner of app shared is live; refusing to boot`, no guest started |
| `app_hold_still_running`, `app_hold_kept_running` | HVH still running after the refusal, then printed `== held` and exited 0 |
| `app_two_builds_same_volume`, `app_second_build_reuses_image`, `app_two_builds_same_key` | HV2 in `shared` afterwards reads HVH's token from the same image; same `/key` peer-id |
| `app_key_matches_app_derivation` | that key = HKDF(HKDF(master, `mac-compose-app-key/1|shared`), `…get-key/1|peer-id`) |
| `app_same_build_other_app_differs` | HV2 in `shared` and HV2 in `dev|HV2` (same master): different `/key` |
| `clientdata_names_app`, `clientdata_names_genesis_app`, `verify_receipts_names_app` | boot clientData carries `"app"`; `verify_receipts.py` prints it |
| `durable_runner_sigkilled`, `durable_runner_died`, `durable_synced_lines_survive_sigkill` | guest appends 3 lines each with `sync -f` and a 4th without, prints `== SYNCED`; the test SIGKILLs its runner (exit 137); `debugfs -R "cat /durable.txt"` on the image shows `synced-1..3`; the unsynced line was lost in this run |
| `task_silent_connection_closed_runner_survives`, `task_silent_connection_close_logged` | silent-connection close now 2 s (see below) |

Found along the way:
- `flock` on the image itself breaks the boot: VZ then refuses the attach (`VZErrorDomain Code=2 "The storage device
  attachment is invalid."`), so the lock is on a sidecar `<name>.ext4.lock`. The first pass failed 15 checks this way.
- The design's legacy rule as first written ("the genesis build" uses the old path) would not cover the live peer: its
  next runner is a new build with a new CDHash, so `app == "<cdhash>|<compose>"` of the booting build is false. The
  runner instead uses the old path whenever the app id itself has the form `<cdhash or dev>|<compose_hash>` and
  `volumes/<cdhash>/<compose_hash>/` exists. `genesis_upgrade_*` test exactly that.
- Three KMSes started at once on one `--state` raced creating `master.key` (`FileExistsError`); the shared-master
  KMSes now start after the first.

Other changes in this pass:
- Compose volumes attach with `vzDiskImageSynchronizationMode=full` (F_FULLFSYNC on the host per guest flush);
  Containerization's default `.fsync` is not flushed to the drive on macOS. Power-loss durability of the ledger rests on
  `.full`. The SIGKILL test above only shows that a guest `fsync` reaches the host file; the coordinator saw the same result with the default
  mode. A power-cut test is not possible on this setup.
- Silent guest connections (no request head) are closed after 2 s, down from 10 s (`Proxy.swift`
  `silentConnectionSeconds`). In a paid run the relay stall cost the peer 10 s on `/attest` and client handshakes timed
  out behind it; real guest clients send their head within milliseconds.

To move the live peer onto this runner: sign a new build (new CDHash `NEW`), start its KMS with
`--allow "003a7d4e…|49e702b3…:NEW:49e702b3…"` and the runner with `--app "003a7d4e…|49e702b3…"`. Its `/key` values and
its ledger at `volumes/003a7d4e…/49e702b3…/` carry over. `~/vz-runner/node.sh` does neither yet. Not done here.
`test/attested.sh` is updated (genesis `--app`, legacy path, app `shared`, `build_not_in_requested_app`) and has not run.

## Limits of this prototype, as built

- The parcel is sealed to the runner but not signed by the KMS. A local process that can answer on the KMS port could
  hand the runner a key of its own choosing; it still cannot read the real one.
- The host end of the proxy is a socket file in the run directory. A local user can connect to it and spend the cap.
- Redaction catches only a literal copy of the key in a response body. An upstream that reflects it encoded (base64,
  JSON-escaped) would pass it to the guest. Allowlisting only non-reflecting endpoints is the real control; httpbin was
  used here because it reflects.
- The token cap is per boot, not per (compose, requester). `max_tokens` bounds output only, so actual usage (input
  included) can exceed the reservation and the remaining budget; the overrun is charged and the next request is refused.
  Anthropic cache tokens (`cache_creation_input_tokens`, `cache_read_input_tokens`) are not counted. A 502 for missing
  usage comes after the upstream call, so that spend is real and is not receipted. A streamed (SSE) body is not
  parsed for usage, so a metered streaming call gets that 502.
- The guest rootfs, kernel and initfs files remain owner-writable between hash and boot (plan §1.3); no dm-verity.
- `docker_compose_file` must be JSON; one service; `command` is the full argv.
- The quote helper's file hash is compiled in and checked before each exec, but the CDHash does not cover node
  (`--node`) or `verify/node_modules` (`@phala/aci-verifier` 0.7.2, `@phala/dcap-qvl` 0.6.6, pinned by
  `package-lock.json` integrity only at install). Someone who can write those can make any quote pass. The file is
  also hashed and then exec'd by path, so a writer racing the two wins.
- Provider quotes: NVIDIA NRAS's JWT signature is not checked (as in the code it was ported from); the NEAR gateway's
  TCB is reported, not gated (abalone's `gatewayTcb: "reported"`); key custody (ACI §9.1 check 5) is not checked; the
  quote is verified once per boot per host, not re-fetched.
- NEAR `onchain` admission trusts the DstackApp owner (NEAR's governance) to allow only reviewed composes, as of the
  block read; it is not a review of the compose. The block and state come from one public RPC
  (`mainnet.base.org`), TLS-pinned to GTS Root R4; an RPC that lies about the chain is not detected (no light client,
  no storage proof, no second RPC). The helper's other fetches (NEAR, NRAS, Intel PCS) still use node's default CA store.
- CONNECT tunnels have no backpressure and no byte or connection cap, and produce no receipts.
- Named volumes are unencrypted ext4 images on the host (Containerization 0.33.4's ext4 formatter has no encryption
  and the guest has no dm-crypt tooling). The Mac owner can read and edit the ledger, and can roll it back by
  restoring an older copy of the image. Accepted at gift size; the peer keeps no sole copy of a secret there. The
  path's CDHash is the runner's own reading of its signature, not the KMS's verified one; a modified runner can
  mount any image on the host. That is no loss while the images are unencrypted. Writes by the guest to the `ro`
  marker mount were not tested. A second runner of the same app is refused by the `<name>.ext4.lock` flock; a modified runner, or one from before app ids (the live node's build `003a7d4e…`), does not take it.
- Task guests: `/out` is read with ContainerizationEXT4's reader, which handles extent trees of depth ≤ 1 and ignores
  extents' logical offsets and the unwritten flag. A sparse or short file is caught (the read must equal `i_size`); a
  preallocated (fallocate) extent is read as data. Symlinks, devices and fifos in `/out` fail the task. The out and
  collect tars are built in memory (several copies of `/out` at once) and served whole. The attach
  stream has no backpressure while attached. `/in` and `/out` are unencrypted files under `<out>/tasks/<id>/` until
  `/task/delete`. The task's own receipt key is bound only through the runner's assertion under the peer enrollment, so
  a verifier trusts the runner binary for that link, as for the peer's own receipts. The test entrypoint (a shell) did not exit on
  SIGTERM, so every stop ended at the SIGKILL; an entrypoint that handles SIGTERM was not tested.
- Guest relay stall (Containerization 0.33.4, see "Signed task pass failure and fix"): a peer connection opened while a
  task VM starts can carry no bytes and block the peer's later connections for up to 2 s, until the runner closes it.
  The peer must retry a request whose connection closes before any response.
