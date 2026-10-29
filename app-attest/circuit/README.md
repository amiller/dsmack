# App Attest leaf circuit

`attest_leaf` verifies the leaf certificate's SHA256/P384 signature, strict DER
and extension policy, nonce, and canonical enrollment authData. Intermediate
root authentication happens once in the shared
[`AppleEndorsements`](../contracts/src/AppleEndorsements.sol) contract.
[`AppleAttestZK`](../contracts/src/AppleAttestZK.sol) binds the proof to an
endorsed subject/key, checks profile and validity, and stores the enrolled key.
The Solidity enrollment and assertion paths use the same endorsement registry.

`install.sh` downloads the pinned nargo, bb, Foundry and solc into the
absolute directory `$ATTEST_TOOLS`; `env.sh` puts them on `PATH`. From this
directory:

```sh
. ./env.sh
./check-leaf.sh fixture.json   # witness generation for one fixture
./prove-leaf.sh                # proofs for the Mac, iPhone and fresh-Mac fixtures
```

Fixture JSON contains hex strings `cert`, `intermediate`, `auth`, and
`clientData`. `prepare-leaf.py` turns a fixture into `Prover.toml`.
Builds run in `tools/attest-build/leaf` under a lock.

`prove-leaf.sh` compiles the circuit, writes the VK, proves and natively
verifies each fixture, checks the public outputs against fixture-derived
values, and regenerates the Solidity verifier. It fails unless the VK and
verifier equal the committed copies in [`verifier/`](verifier/). Proofs go to
the ignored `proofs/leaf`, where `contracts/test/zk` reads them.

The public vector has 24 BN254 fields. Every 32-byte value uses big-endian
hi128 then lo128; P384 coordinates use three big-endian 128-bit limbs each.

| Fields | Value |
|---|---|
| 0–1 | rpIdHash |
| 2–3 | CDHash (`apple_cd_hash_hash_01`) |
| 4–5 | SHA256(clientData) |
| 6–7 | Leaf P256 x |
| 8–9 | Leaf P256 y |
| 10 | Leaf notBefore, Unix seconds |
| 11 | Leaf notAfter, Unix seconds |
| 12 | AAGUID, big-endian 128 bits |
| 13 | Validation category, decoded little-endian u32 |
| 14–15 | SHA256(key-ACL extension value) |
| 16–18 | Intermediate P384 x |
| 19–21 | Intermediate P384 y |
| 22–23 | SHA256(complete issuer Name DER) |

`enrollLeafProof(proof, clientData, p, key, id)` checks the six intermediate
limbs against the shared entry `id` and supplies its subject hash as fields
22–23. Entry IDs are SHA256(abi.encode(subjectSHA256, P384.C384Elm)). It checks
both validity windows at the current block time and stores the intermediate
notAfter as the key's expiry, so an enrolled key outlives its 3-day leaf. The
root cutoff is 2373148800 (2045-03-15). Profile, client-data hash, admission
policy and duplicate-key checks remain on chain.

The parser is `core/src/certificate.nr`. High-s P384 signatures are
normalized inside the circuit to match Solidity. Issuer Name contents and
unknown noncritical extension values are not parsed, as in Solidity.
