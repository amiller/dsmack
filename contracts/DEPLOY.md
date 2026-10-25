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

## Forgery canary

`Canary` pays an armed entry to the first assertion by the entry's runner build
over `forgeryContext(id, claimant)`, a context that build never asserts. An entry
names a CDRegistry `buildId` and counts only while that build is approved, so any
copy the registry admits can claim, including one re-signed by another team: the
approved runner is signed for one device.
Its verifier is a dedicated `AppleAttestRegistryV1` whose `registry` is the
canary, sharing `CDRegistry` and the adapter policy above. Each App Attest key
enrolls there separately (~14M gas), and its assertions must be claimed in
counter order. Deploy the verifier with `registry` = the canary's predicted
address, then the canary, then `arm(0, cds.buildId(), 0, 0, until)` with the pot.

Arm only a build whose every `generateAssertion` prefixes a fixed domain, such
as the `mar` runner. The App Attest probe approved above asserts any file.

On 2026-10-25 `setBuild` replaced the probe with the `mar` runner, CDHash
`0x9e733cee03debdd1080c9de6f1a3cdd23fdacdfb74c15fd48c8fe02069d62bb8` (Apple
Development, `work/guest-attest-20261025`; its assertion domains are launch,
run-result and guest-attest): `setBuild`
`0x1deca4f7e907662529b20a4b0dad0f5cafe903904f05518714bfb7ce0dc948bc` (826,210 gas),
`registerBuild` `0xf3897c9966fe04d18584ffcc8cb63aeeafc7a6bc98ca156ef17f180235d61d11`
(843,101). The probe CDHash no longer resolves.

| Contract | Address | Tx | Gas |
|---|---|---|---:|
| AppleAttestRegistryV1 (canary verifier) | `0xa2b12DEe6D027b409fBaD84d308C9836E5A2587A` | `0x04fd3a766320c80151d4917954f9e64738e5224ec5b4af66ae81c1c7d4868470` | 4,437,597 |
| Canary | `0x469BBd050Cc74914ce9c2C69D049E8923E6D24c0` | `0xb6a06a0a547e49833628b62f079bd19a8e3c2cbe80de987c75ac17bd8994aab6` | 856,891 |

Entry 0: Forgery for the runner CDHash, 0.01 ETH, `until` 1800731481
(2027-01-23), armed in `0x3e73a692eac013701c37939bb5f5b6ec2ad1144d0c7206fd57a167e213fff2b8`.
Both contracts are source-verified on Basescan.

The 2026-10-25 instance (canary `0x7c66C53f45c53c2DDB23aa9B665D593c5845432C`,
verifier `0x5Fd60f7367884dA510E47722F0498f23F6F5d9a7`) predates build binding:
its entry 0 (0.01 ETH, until 2027-01-23) is claimable with the probe and is void
as evidence. The `0x469B…24c0` instance binds one CDHash, so only that signer's
device can claim it, and it stops resolving once a later build is approved.

## Key canaries

Guest (#1), Runner (#2) and Owner (#3) entries pay a P-256 signature over
`claimDigest(id, claimant)` by a canary key whose public key (x || y) is a system event
in a guest Attest assertion by the entry's build. `claimKey` replays the event head,
rebuilds the 255-byte client data and verifies the assertion through `attest`. The log
must end in its only `system-ready` and hold one `canary-guest-key` (Guest, Owner; sent by
the supervisor, key in guest-root tmpfs) or `canary-runner-key` (Runner; appended by the
app, key in its memory). The signature uses the RIP-7212 precompile at `0x100`.
`contracts/canary_claim.py` prints the calldata from a run's attestation and the key.
A burned entry sets `burnedImage[image]` (Guest, Owner) or `burnedBuild[buildId]`.

