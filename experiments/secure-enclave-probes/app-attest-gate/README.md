# app-attest-gate

## Question

Since an SE key is not bound to the binary ([key-binding](../key-binding/)),
can App Attest enforce code identity instead, at the point where a remote party
authorizes an operation?

## Answer

Yes, for a verifier that checks the CDHash on every assertion. A modified build
can reuse the honest build's App Attest key, and its assertion carries a valid
signature under that key, but the authenticated CDHash is the modified one, so
an approved-CDHash policy rejects it (`cdhash_policy_failed`). The 11 October
rerun of the custody experiment also held: a modified build reads a persistent
Keychain secret, but is refused delivery of a memory-only secret that is
released only after an attested check-in.

## Guides

Node admission and the App Attest verifier policy: authorize operations, not
keys, and check the approved CDHash on each assertion. Secret delivery to a
provider should go to a fresh per-process key bound into attestation, not to
Keychain storage.

## How it works

- `Probe.swift` is a minimal App Attest client. `enroll` generates a key and
  attests it over SHA-256 of a challenge file; `assert` asserts with an existing
  key ID. The `-D MODIFIED` build differs in one constant, so it has a
  different CDHash under the same team, bundle ID and entitlements.
- The challenge files are canonical operation bytes: protocol
  `dsmack-near-authorize/1`, account `synthetic.near`, operation
  `issue-inference-key`, recipient, 250000000 nanoUSD, expiry and a random nonce.
- `run_step.sh <step>` copies the chosen build to one fixed app path, launches
  it with `open -n -W`, and captures the binary, `codesign` output and App
  Attest outputs under `captures/<step>/`. Steps: `a-enroll` (honest, new key
  a), `a-assert` (honest, key a), `b-old-key` (modified, key a). The script
  also has `b-enroll`, `b-assert` and `a-restored`, used by the original
  six-step experiment in the AttestNode-era `app/macos/` lab (archived).
- The verifier is `verifier/core.py` in this repository: `verify_attestation`
  then `verify_assertion` against a policy whose CDHash list holds only the
  honest build's hash. The recorded decisions also include a wrong-clientData
  check and a counter replay of each accepted assertion.

The custody result comes from the archived `app/macos/custody/` lab, rerun
unchanged except for the SSH host name and Python import paths. There, a persistent build stores a
synthetic P-256 key in the data-protection keychain and a volatile build
receives a category key in RAM only, encrypted to a fresh ephemeral key that
the process bound into its App Attest enrollment. The coordinator releases the
category key only if the attested CDHash is approved.

## Run

```sh
SIGN_ID=... KEYCHAIN=... KEYCHAIN_PW=... TEAM_ID=... BUNDLE_ID=... PROFILE=... ./run.sh
```

Needs a Mac on macOS 27 with SIP and Full Security (App Attest's Mac key policy)
and an App Attest-enabled development profile for `TEAM_ID.BUNDLE_ID`.
`run_step.sh` refuses to overwrite an existing capture; delete `captures/`,
`active/` and `a.keyId.txt` to start over. The recorded challenges carry fixed
nonces and an expiry of 2026-10-12; a real rerun should write new challenge
files with fresh nonces. Verification is a separate step on any machine with
this repository: feed `captures/*/` to `verifier.core`, as
the archived `app/macos/replay_matrix.py` did for the six-step layout.

## Recorded result

11 October 2026, Mac mini M4 Pro, macOS 27.0 (26A428), Apple Development
signing with hardened runtime.

| Step | Counter | Approved-CDHash decision | Wrong clientData | Replay |
| --- | --- | --- | --- | --- |
| `a-assert` (honest, key a) | 1 | accept | `invalid_assertion_signature` | `counter_replay` |
| `b-old-key` (modified, key a) | 2 | `cdhash_policy_failed` | `invalid_assertion_signature` | `counter_replay` |

Both assertions are under the same key ID. Source: `results/assertions-verification.json`.

Custody rerun `custody-20261011T173325Z` (`results/custody-20261011-summary.json`):

| Step | Admitted | Outcome |
| --- | --- | --- |
| `persist-store` (honest) | yes | Stores key, seals ciphertext |
| `persist-replaced` (modified) | no | Still reads the Keychain item, decrypts and signs under the original key |
| `volatile-first` (honest) | yes | Receives category key, decrypts stored ciphertext, signs |
| `volatile-restart` (honest, after SIGKILL) | yes | Old parcel re-authorized for the new session fails at transport decryption; fresh delivery works, same category key |
| `volatile-modified` | no | Denied new delivery; old parcel fails |

All five attestations passed Apple chain, Mac ACL and code checks; admission is
the CDHash decision. The raw category key was not found in any output.

## Files

| File | Purpose |
| --- | --- |
| `Probe.swift` | App Attest enroll/assert client; `-D MODIFIED` variant (same as `app/macos/Probe.swift`) |
| `run_step.sh` | Launches one step and captures its evidence (same as `app/macos/run_step.sh`) |
| `run.sh` | Builds both variants with `../build-app.sh` and runs the three steps |
| `*.challenge` | Recorded operation challenges |
| `results/assertions-verification.json` | Recorded verifier decisions |
| `results/custody-20261011-summary.json` | Custody rerun summary |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive. Changes: the original
`build.sh` (hardcoded identity and keychain path) is replaced by
`../build-app.sh`; `run.sh` is new. The script that produced
`assertions-verification.json` was not preserved.

The same source tree has a `broker-relay/` variant of this probe (adds
`generate` and `attest-existing` modes, driven over SSH) used for the NEAR
broker experiment; it is not copied here because its verifier depends on the
broker code.


## Limits

- One Mac, one signing credential. The modified build is same-team code, the
  case that matters, but not a different-team or re-signed attacker.
- App Attest proves the CDHash of the process that asked for the assertion. It
  says nothing about what that process does with the request: see
  [attestation-deputy](../attestation-deputy/).
- The custody coordinator is a trusted Python process holding the category key
  in RAM, not a TEE peer or contract. No kernel, swap, hibernation or core-dump
  attack. A failed old delivery is not a forensic erasure claim.
- No real NEAR authority is bound by these challenges.
