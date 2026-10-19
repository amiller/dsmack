# secure-enclave-probes

## Question

What does the Mac Secure Enclave actually bind, revoke and transfer, and what
does App Attest add on top?

## Answer

The SE binds a key to the device, not to the code: any same-user binary that
gets the wrapped blob, or same-team code with the keychain access group, can
use it. Once a key capability has been captured, neither process exit, keychain
deletion nor a nonpersistent key ends its use. No route a third-party app can
use moves a secret from one SE to another, and everything the SE decrypts or
agrees on is handed back to host memory. App Attest is what adds code identity:
each assertion carries the caller's CDHash, so a remote verifier can refuse
modified code. It does not make the approved code's requests authorized.

| Probe | Question | Answer |
| --- | --- | --- |
| [key-binding](key-binding/) | Is an SE key bound to the binary that created it? | No. A different binary signed with both a wrapped CryptoKit key and a persistent SEP keychain key |
| [app-attest-gate](app-attest-gate/) | Can App Attest enforce code identity instead? | Yes, per assertion: modified code reusing the key is rejected on CDHash; secret delivery gated this way refuses it too |
| [key-lifecycle](key-lifecycle/) | Do exit, `SecItemDelete` or nonpersistent keys revoke access? | No. Captured blobs and token attributes keep working after exit and after delete |
| [enclave-transfer](enclave-transfer/) | Can one SE re-encrypt a secret to another without the host seeing it? | Not via any reachable route. 40 private-SPI recrypt requests produced no recrypted output |
| [attestation-deputy](attestation-deputy/) | Does an attested runner make its `/attest` output and helpers trustworthy? | No. Host-chosen data gets a valid assertion, and a substitute `node` captures the NEAR key |
| [decrypt-in-memory](decrypt-in-memory/) | Does SE decryption or agreement keep its output in the enclave? | No. Shared secrets, derived keys and plaintext all come back to host memory |

## Guides

Provider key custody, node admission and per-run secret delivery on Macs. In
short: use SE keys for nonexportable device identity, use App Attest with an
approved-CDHash policy over the exact operation bytes for code identity, deliver
secrets to fresh per-process keys after attested check-in, and do not count on
the SE for revocation, confinement of decrypted data, or node-to-node transfer.

## How it works

Each subdirectory is one probe with its own README. All use synthetic keys and
data only. Native probes are small Swift or Objective-C programs that print
results and controls without printing key bytes. Some are ad hoc signed; the
ones that need App Attest or the data-protection keychain are built as signed
app bundles by the shared `build-app.sh`.

## Run

Each subdirectory has a `run.sh`. All need an Apple-silicon Mac; none run on
Linux. The signed-bundle probes need these environment variables, with no
defaults:

| Variable | Meaning |
| --- | --- |
| `SIGN_ID` | Codesigning identity, e.g. `Apple Development: Name (CERTID)` |
| `KEYCHAIN` | Path of the keychain holding that identity |
| `KEYCHAIN_PW` | Its password, for `security unlock-keychain` |
| `TEAM_ID`, `BUNDLE_ID` | App ID the entitlements and Info.plist use |
| `PROFILE` | Development provisioning profile for `TEAM_ID.BUNDLE_ID`, with App Attest |

`key-binding/verify.py` re-checks recorded signatures anywhere with Python
`cryptography`.

## Recorded result

All runs: Mac mini M4 Pro, macOS 27.0 (26A428), 10–11 October 2026. Each
subdirectory's `results/` holds the compact records and its README the table.
None of these probes have been rerun from this directory; only
`key-binding/verify.py` was run here (15 October 2026, Linux), and it
reproduces the recorded independent verification.

## Files

| Path | Purpose |
| --- | --- |
| `build-app.sh` | Builds and signs a probe as `CodeBindingProbe.app` with App Attest and keychain-group entitlements |
| `key-binding/` | Wrapped-blob and persistent SEP key reuse by a different binary |
| `app-attest-gate/` | App Attest enroll/assert with honest and modified builds |
| `key-lifecycle/` | Exit, delete and nonpersistent-key revocation tests |
| `enclave-transfer/` | Private ECIES recrypt and platform-binding probes |
| `attestation-deputy/` | Runner `/attest` and `QuoteHelper` extractions |
| `decrypt-in-memory/` | Output-exposure contract and two-key bid exchange |

## Provenance

Collected from private research runs of 10–11 October 2026; each subdirectory
describes its changes.
Common changes: signing identity, keychain path and password, team and bundle
ID moved from hardcoded values and a local signing script into environment
variables; home-directory paths and host names removed; SSH orchestration
replaced by local `run.sh` scripts. Large captures (App Attest CBOR, compiled
probes, raw logs) stay in the private evidence directories.

## Limits

- One Mac, one Apple Development credential. No second device, no Developer ID
  or different-team attacker, no iOS.
- No kernel, root, debugger, swap or crash-dump attack. The negative results do
  not need one: ordinary user-level code is enough.
- Negative results cover the APIs and policies tried. Each README names what
  was not tried (user-presence ACLs, private transcode ACLs, SEP-backed `SecKey`
  ECIES and others).
- The `run.sh` scripts reconstruct the recorded command sequences; a few launch
  details were not recorded and are noted per probe.
