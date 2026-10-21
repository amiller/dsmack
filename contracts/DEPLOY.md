# Registry deployment

`CDRegistry` admits re-signed copies of one approved build; `AppleAttestRegistryV1`
admits any App Attest key whose CDHash the registry resolves to the attested RP ID.
They use the Base Sepolia `AppleEndorsements` in
[app-attest/DEPLOY.md](../app-attest/DEPLOY.md).

## Build

The deployed bytecode comes from one solc standard JSON input with
repo-relative source names (forge names files outside its root by absolute
path, which changes the metadata hash). From the checkout root:

```sh
python3 contracts/std_input.py > input.std.json
solc-0.8.21 --standard-json < input.std.json > out.json
```

Basescan verification uses the same input, compiler `v0.8.21+commit.d9974bed`.
`CDRegistry` stores `msg.sender` as an immutable owner, so simulate its
creation with `--from` the deployer when comparing code hashes.

## Approving a runner build

`setBuild` replaces the approved build; CDHashes registered under the previous
build stop resolving. From a signed `Runner.app` on the Mac:

```sh
python3 contracts/cd_args.py Runner.app/Contents/MacOS/runner > build.json
cast send $CDS 'setBuild(bytes,bytes,bytes,uint256,uint256)' <cd> <page0> <ent> <linkeditCmd> <codeSigCmd>  # owner only
cast send $CDS 'registerBuild(bytes,bytes,bytes)' <cd> <page0> <ent>
cast call $CDS 'rpIdHash(bytes32)(bytes32)' <cdhash>   # must equal sha256(application-identifier)
```

`registerBuild` is open to anyone; it only admits copies whose code, masked
page 0, CodeDirectory header and entitlement shape match the approved build.

## Base Sepolia (chain 84532), 2026-10-21

Deployer and owner `0x97883cb4B2f21530277F86490d8881654E36E6aA`. Code hashes
match simulated creation at block 48416348; both are source-verified on Basescan.

| Contract | Address | Tx | Gas | Runtime keccak256 |
|---|---|---|---:|---|
| CDRegistry | `0x6e0f02366c2f09a70da88726910390baeef9f6d8` | `0xb46f2fc78401d5827d5bf5ae61e04ae6df7fc3c508c2611010927ea61c5a9390` | 1,630,427 | `0x6ae3eebb3f1def54c753004cd14ac3990208863dee462f6c3cfcfb76ea938454` |
| AppleAttestRegistryV1 | `0xe49530aa82ddbf157b1cb47825712197ddc5ed5b` | `0xf8995c6917fb553e44b3142224048059885867bd2681ee3854ca62d241bb5556` | 4,437,597 | `0x60727c7bc253780c65f851cfd763cf80f23c65638ee32dc8f226932db943dfe6` |

Adapter policy: registry (the `verify` caller) is the deployer; aaguid
`appattest`; category 3 (Apple Development); ios false.

The approved build is the App Attest probe of
[fixtures/cd-args-probe-macos.json](fixtures/cd-args-probe-macos.json), CDHash
`0x67dfc08f0eca771ae2787870ab3bffc7dfb39a7fac4db6b0c087e58c2f488d70`:
`setBuild` `0x73c803b00510273d5c0b10e28f399d22e6b3264b16c0469c390b7d5fce12fb1f`
(583,790 gas), `registerBuild`
`0x61373e3a24df69529ce3be9ea25fcb3c5b4f7727547647cac87d74d4e49b43bb` (637,464).
The live capture [live-apple.json](../app-attest/contracts/fixtures/live-apple.json)
enrolled in `0x14cc46bfc503ff5931df9a64e68e2aa339911cc17eee8baa8054152c697ddb29`
(14,255,822 gas) and its `a1` assertion verified in
`0x17b6278f10bf7f3d4d6e2361f7c0f01c84f952a4d7d2186cf66fae9eb50fd7db` (195,974).
