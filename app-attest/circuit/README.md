# App Attest leaf circuit

`attest_leaf` verifies the leaf certificate's SHA256/P384 signature, strict DER
and extension policy, nonce, and canonical enrollment authData. Intermediate
root authentication happens once in the shared
[`AppleEndorsements`](../contracts/src/AppleEndorsements.sol) contract.
[`AppleAttestZK`](../contracts/src/AppleAttestZK.sol) binds the proof to an
endorsed subject/key, checks profile and validity, and stores the enrolled key.
The Solidity enrollment and assertion paths use the same endorsement registry.

Toolchain setup and contract/corpus commands are in
[CONTRIBUTING.md](../../CONTRIBUTING.md). Installation and package/CRS caches
are shared outside the checkout via the required absolute `ATTEST_TOOLS` path.
From this directory, after installing the pinned tools with `install.sh`:

```sh
. ./env.sh
./check-leaf.sh fixture.json
./measure-leaf.sh
python3 negative-leaf.py
python3 test-leaf.py
```

`check-leaf.sh` exits zero on successful witness generation. It builds in the
ignored `tools/attest-build/leaf` workspace under a lock. Fixture JSON contains
hex strings `cert`, `intermediate`, `auth`, and `clientData`. `prepare-leaf.py`
extracts the intermediate key and subject hash; it does not authenticate that
certificate. Optional `intermediate_x`, `intermediate_y` and `public_inputs`
allow explicit witness values for negative tests. The adapter is preparation
code; the circuit constrains every public value. Preparation errors are errors,
not evidence of constraint rejection.

`measure-leaf.sh` compiles, measures gates, creates the VK, proves the local
Mac/iPhone/fresh-Mac fixtures, verifies each proof natively, checks all public
outputs against fixture-derived values, generates the Solidity verifier, and
runs its positive and mutation tests. Generated artifacts remain ignored under
`proofs/leaf`.

The reviewed verifier, VK and toolchain pin are committed in
[`verifier/`](verifier/). The default Solidity suite checks their hashes;
`measure-leaf.sh` compares regenerated artifacts with them. Both real-proof
Solidity suites import the committed verifier.

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
both validity windows at the current block time and stores min(leaf notAfter,
intermediate notAfter). The root cutoff is 2373148800 (2045-03-15). Profile,
client-data hash, admission policy and duplicate-key checks remain on chain.

The retained constrained parser lives in `core/src/certificate.nr`. Its only
unconstrained helper chooses a differing OID byte; the caller constrains the
index and inequality. High-s P384 signatures are normalized inside the circuit
to match Solidity acceptance. Issuer Name contents and unknown noncritical
extension values remain opaque, matching Solidity. Native P256 assertion
verification is unchanged.
