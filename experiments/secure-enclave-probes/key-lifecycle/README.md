# key-lifecycle

## Question

Can access to a Secure Enclave key be revoked by ending the process that made
it, deleting its keychain item, or making it nonpersistent? Per-run receiving
keys only reduce exposure if one of these actually ends the key's use.

## Answer

None of them did, once a capability had been captured. A CryptoKit wrapped
blob saved by one process decrypted in a later process, including from a
binary with a different CDHash. After `SecItemDelete` succeeded, a process
already holding the key kept signing, and a new process rebuilt the key from
a 648-byte copy of its token attributes and signed with it. A nonpersistent
SEP `SecKey` was rebuilt the same way after its creator exited. Keychain lookup
did fail after deletion, but lookup failure did not stop use of the key.

## Guides

Per-run custody and key rotation. Fresh per-run keys protect future
deliveries; they do not revoke what a compromised host captured during the
run. Revocation has to come from the peer refusing to send to old keys.

## How it works

- `sep-lifecycle-probe.swift` (CryptoKit). `capture` makes a
  `SecureEnclave.P256.KeyAgreement` key, encrypts a canary to it, and saves the
  envelope plus the key's `dataRepresentation` (`wrapped.blob`). `restore`
  in a new process loads the blob and decrypts, with wrong-key and tamper
  controls. `memory-only` does the same but saves no blob. `run.sh` also
  builds a variant with one extra line appended, so it has a different CDHash.
  It counts visible keychain keys before and after each run.
- `seckey-delete-probe.swift` (Security framework, signed app). `create` makes
  a permanent SEP key (`AfterFirstUnlockThisDeviceOnly` + `privateKeyUsage`)
  under a unique tag and saves its public key, a persistent reference and
  the `SecKeyCopyAttributes` dictionary minus the access-control object.
  `hold` acquires the key and waits; `delete` runs `SecItemDelete` from another
  process; `hold` then signs again. `reopen` tries tag lookup and the saved
  persistent reference. `tokenrestore` calls `SecKeyCreateWithData` with empty
  data and the saved attributes and signs. `transient` does the `create` step
  with `kSecAttrIsPermanent` false. Every signature is verified against the
  saved original public key, with wrong-key and wrong-message controls.

## Run

```sh
SIGN_ID=... KEYCHAIN=... KEYCHAIN_PW=... TEAM_ID=... BUNDLE_ID=... PROFILE=... \
  ./run.sh /path/to/fresh-work-dir
```

Apple-silicon Mac. Part 1 is ad hoc signed and needs no identity. Part 2
builds a signed app with `../build-app.sh` (data-protection keychain needs the
access-group entitlement) and runs its executable directly.

## Recorded result

11 October 2026, Mac mini M4 Pro, macOS 27.0. Records in `results/`.

CryptoKit wrapped blob (`sep-lifecycle-results.json`):

| Case | Observed |
| --- | --- |
| `capture` | 284-byte blob, local decrypt ok, creator exits |
| `restore`, new process | Same public key, canary decrypts, wrong key and tamper rejected |
| `restore` from changed binary | Decrypts; CDHash `803e19ac…` vs `6255a622…`, both ad hoc, no team |
| `memory-only`, then `restore` | Local decrypt ok; restore fails, no blob file (exit 1, as expected) |
| Visible keychain keys | 9 before and after every case |

SecKey deletion (`seckey-delete-results.json`, one process per row):

| Step | Observed |
| --- | --- |
| `create` | Signs; private export rejected; persistent ref and 648-byte token attributes saved |
| `hold`, before delete | Signs under original key |
| `delete` (other process) | `SecItemDelete` = 0 |
| `hold`, after delete | Still signs under original key; lookup now -25300 |
| `reopen` | Tag lookup and persistent ref both -25300 |
| `tokenrestore` | Rebuilds key, signs under original key |
| `transient` then `tokenrestore` | No keychain item or persistent ref; new process rebuilds key and signs |

`seckey-transient-token-results.json` is an earlier transient run with the same
outcome, before the original-public-key checks were added.

## Files

| File | Purpose |
| --- | --- |
| `sep-lifecycle-probe.swift` | CryptoKit capture/restore/memory-only probe |
| `seckey-delete-probe.swift` | SecKey create/hold/delete/reopen/tokenrestore/transient probe |
| `run.sh` | Builds and runs both sequences |
| `results/*.json` | Recorded stdout and exit codes per mode |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive. The probe sources (SHA-256 `c383f481…` and `1156b68d…`) match the
recorded runs. Sources copied
unchanged; `run.sh` is new and reconstructs the order of the recorded runs.
How the original changed-code variant was edited and how the signed SecKey
probe was launched were not recorded.

## Limits

- `tokenrestore` uses an implementation-derived path (token ID and object ID
  in the attributes), not a documented serialization. Apple DTS says retained
  `SecKey` behavior after `SecItemDelete` is undocumented. The result is what
  this configuration does, not a contract.
- Only `privateKeyUsage` without user presence was tested. App Attest keys,
  user-presence policies and other ACLs were not.
- `memory-only` shows only that no blob was saved by the probe. It says nothing
  about framework memory, swap or crash residue.
- No kernel exploit. Capturing the blob or attributes assumes code running as
  the user during the run.
