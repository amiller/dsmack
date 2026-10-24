# App Attest verification

On-chain verification of Apple App Attest enrollments and assertions, in two
forms that share one endorsement registry and store the same key record.

- Solidity path ([MacAppAttestV1](contracts/src/MacAppAttestV1.sol)): parses the
  leaf certificate as strict DER and checks its P384 signature, nonce,
  enrollment authData, app identity, code hash and platform policy.
- ZK path ([MacAppAttestZKV1](contracts/src/MacAppAttestZKV1.sol)): the Noir
  [leaf circuit](circuit/) proves the same leaf checks, and the adapter binds
  its 24 public fields to an endorsed intermediate, policy, client data and
  validity window.

Both paths verify later assertions with the native P256 precompile.

[AppleEndorsements](contracts/src/AppleEndorsements.sol) checks each Apple
intermediate once against the P384 key in
[Apple's App Attestation root](../trust/apple-app-attestation-root.pem). Any
root-signed intermediate that meets the CA policy can be endorsed. Enrollment
checks the intermediate's subject, key and expiry.

## Layout

- `contracts/src`: adapters, parsers, P384 and SHA384.
- `contracts/test`: Foundry tests; `test/zk` runs against real leaf proofs.
- `contracts/fixtures`: Apple captures from a Mac, an iPhone and a fresh Mac,
  the Apple intermediate, and `rotation/` test CAs made by
  `test/make-intermediates.py`. The captures contain the attested key, App ID,
  app and OS versions, validity window and nonce; no device identifier.
- `contracts/verifier`: builds the committed Honk verifier with solc 0.8.27.
- `circuit/`: the leaf circuit, proving scripts and the committed verifier.

## Running

From the checkout root, after installing the tools (see
[CONTRIBUTING.md](../CONTRIBUTING.md)):

```sh
./test.sh
```

`forge test --root app-attest/contracts --offline --use "$SOLC" --gas-report`
prints per-call gas. [DEPLOY.md](DEPLOY.md) gives artifact and address checks.
