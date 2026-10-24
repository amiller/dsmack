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

`setBuild` with a different build replaces the approved build. CDHashes
registered under the previous build stop resolving, and because the adapter
calls `admit` on every assertion, keys already enrolled under them stop
verifying too. (Calling `setBuild` again with the same build keeps `buildId`, so nothing changes.)
`measure` finds the masked `__LINKEDIT` and `LC_CODE_SIGNATURE` load commands
in page 0 itself. From a signed `Runner.app` on the Mac
(`lipo -thin arm64` a universal binary first):

```sh
python3 contracts/cd_args.py Runner.app/Contents/MacOS/runner > build.json
b(){ python3 -c "import json,sys;print(json.load(open('build.json'))[sys.argv[1]])" $1; }
cast send $CDS 'setBuild(bytes,bytes,bytes)' $(b cd) $(b page0) $(b ent)  # owner only
cast send $CDS 'registerBuild(bytes,bytes,bytes)' $(b cd) $(b page0) $(b ent)
cast call $CDS 'rpIdHash(bytes32)(bytes32)' $(b cdhash)   # must equal sha256(application-identifier)
```

`registerBuild` is open to anyone; it only admits copies whose code, masked
page 0, CodeDirectory header and entitlement shape match the approved build.

## Base Sepolia (chain 84532), 2026-10-21

Deployer and owner `0x97883cb4B2f21530277F86490d8881654E36E6aA`. Code hashes
match simulated creation at block 48557028 (after both deployments); both are source-verified on Basescan.

| Contract | Address | Tx | Gas | Runtime keccak256 |
|---|---|---|---:|---|
| CDRegistry | `0xd6567da581bcca8ce965cd16785a43acbf3378f6` | `0xf48e9fa672e97a77aefb07c402272e93ace867f22f34def9fe4012850559896d` | 1,872,385 | `0xc731e977920a0c492f2645e84458657ad5a0b6520b51726bed94ffaac23c606e` |
| AppleAttestRegistryV1 | `0x697b314619eaafcadd0b6bda03590e31260d8670` | `0x934123b57cc37cb2bd3eb04cee787105aa2929b250a97fdfc2c75955db921638` | 4,437,597 | `0x85fff6a3e392d493a75202b35e225a2507ce5720fe07f88ceac374de40d9198f` |

Adapter policy: registry (the `verify` caller) is the deployer; aaguid
`appattest`; category 3 (Apple Development); ios false.

The approved build is the App Attest probe of
[fixtures/cd-args-probe-macos.json](fixtures/cd-args-probe-macos.json), CDHash
`0x67dfc08f0eca771ae2787870ab3bffc7dfb39a7fac4db6b0c087e58c2f488d70`:
`setBuild` `0xc230c7f5866e3c202c43cc82517fe33e89adcd18527aab4fb9934e925bd1b954`
(611,311 gas), `registerBuild`
`0x4f9b7676277d19a10b03a9d68e41105f3fa44b08252d1dee1cdfaeb5173b405c` (672,305).
The live capture [live-apple.json](../app-attest/contracts/fixtures/live-apple.json)
enrolled in `0x6e4b6ccc2a8fe7e8d72ad50db673b74f75c2f0378eae4fd37b9989298e629f78`
(14,255,800 gas) and its `a1` assertion verified in
`0xdb21e46ffa14de4bb5da72a35dafe5d3480b86ad5b32940018dc97936dc8e5db` (195,952).
