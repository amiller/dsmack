# Historical runner enrollment fixture

These three public verification inputs were captured at the signed runner boot
`attested-20261008T145504` on 2026-10-08, and selected from its `boot/` directory.
They contain an Apple attestation, public App Attest key identifier and public
boot client data (compose hash, challenge nonce and receipt public key). No
private signing key, provider credential, encrypted key parcel, logs or workload
outputs are included. Selection does not publish the original directory/history.

The capture predates assertions/re-enrollment: it has no `enrolled_at` and no
assertion. The portable test checks at a historical certificate-valid date that
its Apple-rooted enrollment passes, then **refuses** it at the missing enrollment
age. It does not qualify a fresh identity, replay, current issuer or inference.

Exact selected SHA256 values:

- `attestation.cbor`: `2e75a9a5c927cd50fa77eb198f1f4857f8aaae3e6d42730aa9f5d39fd9252bdc`
- `clientData.bin`: `cbb2eb9473ec1326ad2308fc6bce32c717b57b6574c255557581663761a09cc4`
- `keyId.txt`: `20d33868aeeab2ace119b9bc2ee3208f7970d83dca26de005c44333d071de66e`
