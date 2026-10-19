# enclave-transfer

## Question

Can one Mac's Secure Enclave hand a secret to another's without either host
seeing it in plaintext? The concrete lead is Apple's private ECIES
transcode/recrypt SPI, which re-encrypts SE-held ciphertext to a recipient
certificate chain. A side question: can platform-bound key flags be verified?

## Answer

Not through any route a third-party app can reach on a stock Mac. Across six
probes and 40 recrypt requests, no request returned recrypted ciphertext. One
argument layout silently returned the original plaintext. The others failed
with `unable to recrypt` (CryptoTokenKit -1 / AKS `0xe00002e6` for an ordinary
key, -3 / `0xe007c016` with the private ApplePayEnabled flag), whatever the
ACL, certificate chain or token provider. Apple's own regression uses a
private transcode-only ACL, a test keybag and an Apple test chain, none of which
are available. Platform-bound key flags are accepted at creation, but no
attestation could be obtained to show they are enforced.

## Guides

Data replication between nodes. Do not plan on SE-to-SE transfer: secrets
move between nodes through host-visible key agreement
([decrypt-in-memory](../decrypt-in-memory/)) under attested admission
([app-attest-gate](../app-attest-gate/)).

## How it works

Each probe is a small Objective-C program that resolves private Security
symbols with `dlsym`, creates ephemeral SE P-256 keys only, encrypts a public
fixture to each, and asks for recrypt to a synthetic recipient. Before any
request, it imports the recipient's private key in memory, checks it matches
the certificate and runs an ordinary ECIES round trip. Any non-plaintext output
would be decrypted with the recipient key and compared to the fixture; only
`recipient-decrypt-matches=1` would count as success. Exit 0 means the probe
finished, not that transfer worked.

| Probe | Varies |
| --- | --- |
| `probe.m` | Ordinary vs ApplePayEnabled key; header-nested vs regression-test argument layout |
| `acl_certificate_probe.m` | 4 keys: `privateKeyUsage` vs default-allow ACL × ApplePayEnabled; valid, corrupt-signature and truncated certificate |
| `chain_format_probe.m` | Own 3-certificate chain vs leaf only vs corrupt vs truncated |
| `provider_route_probe.m` | `com.apple.setoken` vs `com.apple.setoken:aks` provider × ApplePayEnabled × 4 chains |
| `platform_binding_probe.m` | Key with and without PCC's `kSecKeyOSBound` / `kSecKeySealedHashesBound`; self-attestation |
| `eligible_attestor_probe.m` | Own `SecureEnclaveAttestation` key attesting ordinary and flagged keys |

`prepare_chain.py` builds an own root/intermediate/leaf chain with OpenSSL.
`recipient_x963.py` converts the leaf's SEC1 key to X9.63. `bounded.py` runs one
command with a timeout and kills its process group on expiry.

## Run

```sh
./run.sh provider_route_probe /path/to/fresh-work-dir
```

Any probe name from the table, without `.m`. Stock Apple-silicon Mac,
Xcode command line tools, OpenSSL, ad hoc signing, no entitlements. Uses
`ecparam -name prime256v1`: LibreSSL's `req -newkey ec` writes explicit curve
parameters that the Security import path rejects.

## Recorded result

10–11 October 2026, Apple M4 Pro, macOS 27.0 (26A428), SDK 27.0. Logs in
`results/<probe>.log`.

| Probe | Requests | Outputs | Result |
| --- | --- | --- | --- |
| `probe` | 4 | 0 recrypted | Header layout returned the 47-byte original plaintext (both keys); regression layout CTK -1 / -3 |
| `acl_certificate_probe` | 12 | 0 | Ordinary keys CTK -1 / AKS `0xe00002e6`; ApplePayEnabled CTK -3 / AKS `0xe007c016`; identical across certificate cases |
| `chain_format_probe` | 8 | 0 | Same two errors for every chain form |
| `provider_route_probe` | 16 | 0 | Both providers returned their own token (key type 73); same two errors |
| `platform_binding_probe` | — | — | Both keys created and signed; returned attributes omit the flags; self-attestation CTK -6 ObjectNotFound |
| `eligible_attestor_probe` | — | — | Attestor key created on the AKS token; attestation of both targets CTK -6, zero bytes |

Recipient controls passed in every run.

## Files

| File | Purpose |
| --- | --- |
| `*.m` | The six probes above |
| `prepare_chain.py`, `recipient_x963.py`, `bounded.py` | Fixture and timeout helpers |
| `run.sh` | Prepares the fixture for one probe, compiles, signs and runs it |
| `results/*.log` | Recorded probe output |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive. Every `.m` matches the copy kept with its run; `results/probe.log` is the
named run's log and the others are each increment's `run.log`. Sources unchanged;
`run.sh` collects the fixture and build commands from the original README.

## Limits

- Negative result for the routes tried, not proof that Apple's private
  transcode never works. The exact transcode ACL constant is in a private
  header that is not in the SDK, and a production recipient credential is not
  available to an ordinary developer. Neither was guessed.
- Even a successful recrypt returns ciphertext, not an SE-resident key handle,
  and does not let the caller choose which code may receive the secret.
- CTK -3 means corrupted data, not entitlement denial. AKS `0xe007c016` has no
  known name.
- Platform-bound flags would protect against boot-state changes, not against
  modified same-team code or a runtime kernel compromise. Their enforcement is
  unverified.
