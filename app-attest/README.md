# App Attest verification

The Solidity path checks strict certificate DER, the leaf's P384 signature,
nonce, enrollment authData, app identity, code hash and platform policy.
The ZK path proves the same leaf checks with the pinned Noir leaf circuit;
the adapter binds its 24 public fields to an endorsed intermediate, policy,
client data and validity. Both paths store the key for native P256 assertions.

[AppleEndorsements](contracts/src/AppleEndorsements.sol) verifies intermediates
against the P384 key in [Apple's App Attestation root](../trust/apple-app-attestation-root.pem).
The root certificate SHA256 fingerprint is
`1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`.
Any root-signed intermediate satisfying the CA policy is eligible. Endorsement
is shared once per intermediate; enrollment checks its subject, key and expiry.

[CONTRIBUTING.md](../CONTRIBUTING.md) gives setup and all test commands.
[DEPLOY.md](DEPLOY.md) gives artifact and address checks.
The [circuit](circuit/) and [rule corpus](corpus/) document their interfaces.

Historical native-path measurements on zed (Intel Xeon E-2276G), Base mainnet
fork block 52862340; real-apple.json and apple-intermediate.der. Deployment
excluded. USD uses the original measured L1 fee
and historical quote ($2,441.77/ETH and 0.006 gwei on 2026-10-20); these are not new layout-move benchmarks.

| Path | Total L2 gas | USD |
|---|---:|---:|
| Endorse once | 15,172,225 | $0.222327 |
| Solidity enroll | 14,520,608 | $0.212834 |
| Leaf ZK enroll (current pinned verifier, phase3-r) | 4,698,434 | — |

The leaf ZK gas is the phase3-r measurement with the current pinned verifier;
its historical USD figure is omitted rather than repriced. Source: local
`results/phase3-r.md`, `LeafEnrollmentTest`, original Mac proof on zed,
Base Sepolia fork block 48371278.

Measurement commands from the checkout root, after sourcing circuit/env.sh:

```sh
forge test --root app-attest/contracts --offline --use "$SOLC" --hardfork osaka --fork-url https://mainnet.base.org --fork-block-number 52862340 --match-contract IntermediateTest -vv
FOUNDRY_PROFILE=real forge test --root app-attest/contracts --offline --use "$SOLC" --hardfork osaka --fork-url https://sepolia.base.org --fork-block-number 48371278 --match-contract LeafEnrollmentTest -vv
```

Apple fixtures shared by both projects live only in `contracts/fixtures` here:
this keeps the certificate/parser inputs with their implementation. The dsmack
project reads those paths directly and retains its build-registry fixtures in
`../contracts/fixtures`. Generated proofs are not committed.
