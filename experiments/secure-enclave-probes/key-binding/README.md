# key-binding

## Question

Is a Secure Enclave key bound to the binary that created it? If binary A
creates an SE key, can a different binary B, with a different CDHash, use it?

## Answer

No binding to the binary. In both tested storage forms, B signed under A's key:
a CryptoKit wrapped blob reopened by an ad hoc binary with a different CDHash,
and a permanent Security-framework SEP key looked up by a modified build
signed with the same team, app ID and access group. Adding a legacy `SecAccess`
ACL to the SEP key creation request fails with `-50` (paramErr). The public
`SecAccessControl` flags have no CDHash constraint.

## Guides

Provider key custody. An SE key proves "this Mac", not "this code". Code
identity has to come from somewhere else; [app-attest-gate](../app-attest-gate/)
shows a remote verifier enforcing it.

## How it works

- `wrapped-blob.swift` creates a `SecureEnclave.P256.Signing` key
  (`AfterFirstUnlockThisDeviceOnly` + `privateKeyUsage`, no user presence) and
  writes its `dataRepresentation` (the opaque wrapped blob) to a 0700 state
  directory. Phase `create` (binary A) makes the key and signs two synthetic
  fixtures (a SIWE-style login and a session grant). Phase `reopen` (binary B,
  built with `-D VARIANT_B`, so a different CDHash) loads the blob, checks the
  public key matches, and signs the same fixtures. Each signature is checked
  in-process against wrong-domain, wrong-key, double-hash and tamper controls.
- `persistent-sep.swift` creates a permanent SEP P-256 key in the
  data-protection keychain (`WhenUnlockedThisDeviceOnly` + `privateKeyUsage`)
  under a tag. The `-D MODIFIED` build looks the key up by tag and signs. The
  honest build also tries to add a legacy `SecAccess` object alongside the SEP
  access control and records the error.
- `verify.py` checks all signatures off the Mac with Python `cryptography`.

## Run

```sh
SIGN_ID=... KEYCHAIN=... KEYCHAIN_PW=... TEAM_ID=... BUNDLE_ID=... PROFILE=... \
  ./run.sh /path/to/fresh-work-dir
python3 verify.py results     # anywhere; checks the recorded signatures
```

`run.sh` needs an Apple-silicon Mac. The wrapped-blob part uses ad hoc signing
only. The persistent part builds signed app bundles with `../build-app.sh`
(Apple Development identity, provisioning profile, keychain access group) and
leaves one synthetic permanent key under a timestamped tag. To rerun `verify.py`
on a fresh run, copy its `public-*.json` and `signature.json` files into a
results directory with the names used here.

## Recorded result

11 October 2026, Mac mini M4 Pro, macOS 27.0 (26A428).

| Case | Observed |
| --- | --- |
| Wrapped blob, A creates, B reopens | Both print `controls=pass samePersistedPublicKey=true`; CDHashes `5da9e56b…` (A) and `982f48d0…` (B), both ad hoc |
| Wrapped blob, independent check | 4 signatures valid under one key, wrong message rejected (`independent-verification.json`) |
| Persistent SEP key, honest creates, modified signs | Same public key `04fc285f…`, both signatures verify; CDHashes `06991879…` vs `d424d227…` |
| Legacy `SecAccess` + SEP access control | `SecAccessCreate` = 0, key creation fails `-50` paramErr |

`python3 verify.py results` reproduces `independent-verification.json` exactly
and verifies both persistent-key signatures (checked 15 October 2026 on Linux).

## Files

| File | Purpose |
| --- | --- |
| `wrapped-blob.swift` | CryptoKit wrapped-blob signer; `-D VARIANT_B` gives binary B |
| `persistent-sep.swift` | Security-framework permanent SEP key; `-D MODIFIED` looks it up instead of creating it |
| `run.sh` | Builds and runs both cases on the Mac |
| `verify.py` | Off-Mac signature check of the recorded or fresh results |
| `results/create-A.txt`, `reopen-B.txt` | Probe stdout for A and B |
| `results/public-create.json`, `public-reopen.json` | Public key, messages, signatures and control outcomes |
| `results/independent-verification.json` | Recorded independent check |
| `results/persistent-sep-*.json` | Persistent-key signatures, legacy-ACL error, recorded verification |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive.

Changes: A.swift and B.swift differed only in the printed variant letter; they
are now one file with `-D VARIANT_B`. The hardcoded state directory became
the second argument. The persistent key tag became an argument (it was a fixed
string). The signed-bundle build moved to the shared `../build-app.sh` with
identity, keychain and password from the environment. `run.sh` and `verify.py`
are new; the original verification script was not preserved, and the exact
launch method for the persistent-key binaries was not recorded.

## Limits

- One Mac, one signing credential. B is either ad hoc or same-team.
- Explicit exact-code keychain ACL construction beyond the one legacy
  combination was not tested. This does not rule out every possible ACL
  design, only the supported public paths that were tried.
- No root, kernel, debugger or memory attack. The point is that no attack is
  needed: B is an ordinary program.
