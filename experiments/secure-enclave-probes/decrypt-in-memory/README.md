# decrypt-in-memory

## Question

When the Secure Enclave decrypts or agrees on a key, where does the result go?
Is there a public API that keeps the derived key or plaintext inside the
enclave, so the host never sees it?

## Answer

No such API was found. Every tested agreement, decapsulation and decryption
returns its result to host code: ECDH gives a 32-byte `SharedSecret` the host
can read, ML-KEM decapsulation gives a `SymmetricKey`, HPKE `open` returns
plaintext, and `SecKey` ECDH/ECIES return `CFData`. The SE keeps the private
key; it does not keep what the key unlocks. A two-key sealed-bid exchange on
one Mac works, but the auctioneer's host process can read every bid.

## Guides

Any design that hopes the SE confines decrypted data: it does not. The SE
gives nonexportable identity and agreement keys. Confidentiality of what they
unlock rests on the admitted code ([app-attest-gate](../app-attest-gate/)) and
the OS, not on the enclave.

## How it works

- `se_contract_probe.swift` runs each CryptoKit SE operation (P-256 signing and
  agreement, HPKE with an SE recipient, ML-KEM-768, ML-DSA-65) and records the
  result type and how many bytes host code can read, without printing key
  bytes. `full` also persists P-256 and ML-KEM wrapped keys; `reuse` reloads
  them in a new process and opens the earlier ciphertexts. Each check has an
  explicit expectation; any failure exits nonzero.
- `se_auction_envelope_probe.swift` runs a first-price sealed-bid fixture as
  separate processes: bidder and auctioneer each generate an SE agreement key,
  then derive a transcript-bound key (protocol, auction ID, both public-key
  fingerprints, context) and exchange two bid envelopes. Controls: tamper,
  wrong context, wrong auction, a third unrelated SE key.
- `seckey_ecies_probe.swift` checks the Security-framework `SecKey` ECDH and
  ECIES return types with temporary nonpersistent software keys.

## Run

```sh
./run.sh /path/to/fresh-work-dir
```

Apple-silicon Mac, macOS 26+ (ML-KEM/ML-DSA), Xcode command line tools. Ad hoc
signing, no entitlements. Each probe runs in its own fresh 0700 directory;
`full` refuses to run where its fixtures already exist.

## Recorded result

10 October 2026, Mac16,11 (M4 Pro), macOS 27.0 (26A428), Xcode 27.0, Swift 6.4.
All runs `verdict=PASS`. Logs in `results/`.

| Operation | Host receives |
| --- | --- |
| SE P-256 signing | Signature (71 bytes DER); wrapped key 284 bytes |
| SE P-256 agreement | `SharedSecret`, 32 bytes readable; HKDF key usable by host AES-GCM |
| HPKE, SE recipient | Plaintext `Data`; no API returns the KEM secret |
| SE ML-KEM-768 decapsulate | `SymmetricKey`, 32 bytes readable; wrapped key 1449 bytes |
| SE ML-DSA-65 signing | Signature 3309 bytes (key not persisted) |
| `SecKey` ECDH (software keys) | `CFData`, 32 bytes |
| `SecKey` ECIES decrypt (software keys) | `CFData` plaintext, 52 bytes |

`reuse` reloaded the signing, agreement and ML-KEM keys in a new process and
opened the original ciphertexts. The auction derived matching key fingerprints
on both sides, opened both bids and rejected all four controls. Its log states
the outcome directly: `host_reachability=ecdh_secret+derived_key+all_bid_plaintexts
readable by auctioneer host process memory`.

## Files

| File | Purpose |
| --- | --- |
| `se_contract_probe.swift` | Output-exposure probe, modes `full`, `reuse`, `cleanup` |
| `se_auction_envelope_probe.swift` | Two-SE-key bid exchange, one mode per process |
| `seckey_ecies_probe.swift` | `SecKey` ECDH/ECIES return types |
| `run.sh` | Builds and runs all three in order |
| `results/*.log` | Recorded environment and probe output |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive. Sources match the SHA-256
hashes printed on the Mac. The original task's
`continue_mac.py` drove the run over SSH; `run.sh` replaces it with the same
command sequence run locally. Sources unchanged.

## Limits

- One Mac. The two-key exchange is same-device, not a two-device test, and has
  no attestation, code identity, freshness or replay checks.
- The `SecKey` probe used software keys. SEP-backed `SecKey` ECDH/ECIES was not
  run; the conclusion there rests on the API's documented `CFData` return and
  Apple's published adaptor source (`SecKeyAdaptors.m`), not on a measurement.
- Absence of an opaque-handle API is from the CryptoKit interface and the public
  `SecKey` exchange/decrypt calls inspected, not every Apple API.
- No memory-reading attack was run; the point is that the host is handed the
  values through ordinary return values.
- ML-DSA-65 persistence and ML-DSA-87/ML-KEM-1024 were not tested.
