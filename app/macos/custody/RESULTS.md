# Persistent and memory-only custody — real Mac tests, September 16, 2026

**Result:** the tested Keychain configuration permits modified code to recover an
earlier application's stored key. The memory-only alternative passes the tested
crash/restart controls: a restarted process cannot reuse an old delivery and regains
the same category key only after a fresh approved check-in and encrypted delivery.

## Persistent storage result

The honest probe generated a disposable P-256 signing key and stored its raw bytes
in the macOS data-protection Keychain, under a unique experiment account, with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. The access group was
`DC9JH5DRMY.dev.dsmack.provider`. It also saved an AES-GCM ciphertext encrypted under
SHA256 of the private-key bytes.

We replaced the app at the same path with different code signed by the same Apple
Development credential, with the same app ID, version and access group. The modified
app successfully read that Keychain item, signed a new verifier challenge under
the original public key, and decrypted the previously stored ciphertext. Its
fresh Apple-rooted attestation carried a different CDHash and failed the honest
code policy. That rejection did not prevent use of the already stored key.

This demonstrates a failure of **this storage configuration** to bind key access
to approved code. It is not an exhaustive result about every Keychain ACL, Secure
Enclave wrapping construction, or storage API. The synthetic Keychain test items
remain under the experiment's unique service/account names; no existing user item
was read, changed or removed.

## Memory-only construction and results

The volatile probe is a separate compiled executable, with no Keychain persistence
branch. On each launch it creates a fresh P-256 ECDH private key in RAM. Its App
Attest client data binds the ephemeral public key, protocol, fresh network challenge
and session. The test authority verifies the pinned Apple chain, exact nonce/key
bindings, Mac SIP/Full Security ACL, and approved CodeDirectory SHA-256.

After acceptance, the authority encrypts a synthetic category signing key to that
ephemeral receiver using ECDH + HKDF-SHA256 + AES-GCM. Each parcel additionally has a
network signature checked against a public key compiled into the measured probe.
The received key signs a fresh challenge and decrypts an existing synthetic data
ciphertext; neither the category private key nor transport private key is written
by the app. The independently verified signatures establish that both accepted
processes used the same category signing key.

| Test | Observed result |
|---|---|
| Approved first process checks in | Receives category key; decrypts stored data; signature verifies |
| Kill that exact process with SIGKILL | Process holding the delivered key terminates |
| Restart approved code with a new ephemeral key | No category key available before delivery |
| Replay previous parcel | Rejected in the first complete run |
| Reauthorize old ciphertext for the new session without re-encrypting | Network signature passes; transport decryption fails; category key still absent |
| Fresh check-in and newly encrypted parcel | Same category public key; fresh valid signature; same stored data decrypts |
| Start modified code | Apple-rooted evidence valid, but CDHash admission rejects; no new category-key delivery |
| Replay old parcel to modified process | Rejected; no category key obtained |

The stronger replay control was performed in `custody-20260916T173508Z`; its recorded
failure is `transport_decryption`, CryptoKit authentication failure, not merely a
wrong-session network signature. Both transport keys and session-bound derivation
change; this experiment does not isolate each anti-replay mechanism separately.

## Evidence and replay

Two complete runs reproduced the persistent-key recovery and the successful
memory-only fresh-check-in path:

- `custody-20260916T173339Z`: original-parcel replay control.
- `custody-20260916T173508Z`: stronger reauthorized-old-ciphertext control; canonical
  evidence bundle with source snapshots, five captures and SHA-256 manifest.

Earlier incomplete run directories are retained as diagnostics. The first delivery
attempt used a non-atomic file upload and failed before a usable category key was
obtained. Deliveries now upload to a staging name and atomically rename before the
receiver reads them. Those incomplete runs are not counted as successful experiments.

```sh
python3 ios-app-attest/macos/custody/verify_evidence.py \
  ios-app-attest/macos/custody/custody-20260916T173508Z
PYTHONPATH=ios-app-attest python3 -m pytest -q ios-app-attest/tests
```

After certificate expiry, add `--at-time 1789581600` (September 16, 2026, 18:00 UTC)
for historical evidence replay only. An archived challenge or historical validation
time must not authorize a new live admission.

The replay checks Apple-rooted evidence, exact expected challenge/session bindings,
CodeDirectory page hashes, matching/different code identities, persistent-key and
category-key signatures, parcel authority signatures, and the replay ciphertexts.
Recorded negative outcomes and process termination remain lab observations, not
cryptographic proofs that no other recovery path exists.

Validation: **51 combined Python tests pass**, including real custody transcript
replay, rejection of an attacker-substituted ephemeral receiver key, and rejection
of a claimed network authority that differs from the one embedded in measured code.

## Scope and consequence for the paper artifact

- Hardware: one M4 Pro Mac, macOS 27.0 (26A428), same signing credential, Hardened
  Runtime, no `get-task-allow`. No OS security settings or keychain ACLs changed.
- A Python coordinator held the synthetic category key and network signing key in
  RAM. It models the releasing peer; it is **not** an attested peer, a smart
  contract, or a demonstration of distributed category bootstrap.
- SSH transported public attestations and signed ciphertexts and controlled lab
  processes. Successful key delivery did not rely on SSH alone for authenticity
  or confidentiality. No raw category key was found in the experiment's saved
  outputs; this bounded scan is not disk/memory forensics.
- Kernel attacks, swap/hibernation recovery, core dumps, debug bypasses and malicious
  dynamic dependencies were not tested. A process can retain the key while alive;
  network revocation does not erase its memory or undo an earlier release.

**Artifact design:** do not persist the category key, a wrapping key that can
recover it, or another equivalent recovery secret on this path. Bind a fresh
process transport key to fresh attestation and check the current code policy before
each new release. A persistent App Attest identity key may authenticate a check-in,
but must not itself unlock the category secret. At least one surviving holder or
separate recovery arrangement must retain the category key; losing all volatile
copies loses access to the ciphertext.

Sources: [Apple keychain access groups](https://developer.apple.com/documentation/security/ksecattraccessgroup),
[Apple App Attest validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
Hardware conclusions are supported by the saved transcripts, not inferred solely
from those documents. ST contracts remain deferred; no contract was changed here.
