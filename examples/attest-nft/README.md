# Attested Mac NFT

The smallest dsmack example: a 70-line Mac app gets an App Attest key, and a contract mints one
non-transferable token per Apple chip to whoever that key names. The token's on-chain SVG shows the
chip's name and a core pattern drawn from the chip. The contract accepts the key only if Apple's
assertion carries the CDHash of a copy of one approved build. Anyone can sign that copy, including
you with your own Apple Developer team, and register it on chain without asking the deployer.

No VM, relay, coordinator or wallet in the app. Everything after Apple's signature is checked in
Solidity.

## What is checked where

| Step | Who | Contract check |
|---|---|---|
| Approve a build | deployer, once | `CDRegistry.setBuild` measures the executable: code pages, page 0 with the three signature-size fields masked, CodeDirectory header, entitlement keys |
| Register a copy | anyone | `CDRegistry.registerBuild` accepts a copy whose measurement matches; its CDHash and App ID are recorded |
| Enroll a key | anyone | `AppleAttestAnyBuildV1.enroll` checks Apple's certificate chain to the App Attest root, the key's macOS policy, and that the attested CDHash was registered |
| Claim | anyone submits | `AttestNFT.claim` checks a fresh assertion over `sha256("dsmack.example.attest-nft/2" ‖ chainid ‖ nft ‖ to ‖ chip ‖ chipId ‖ device)`, that its CDHash belongs to the pinned build, and one token per `device` |

The app reads `chip` (`machdep.cpu.brand_string`), `chipId` and the ECID (`chip-id`, `unique-chip-id`
in `IODeviceTree:/chosen`) itself, and sends `device = sha256("dsmack.example.attest-nft/device/1" ‖ nft ‖ ECID)`,
never the ECID. Apple's evidence carries none of these; they are as trustworthy as the Full Security
macOS kernel the key's access policy requires. The app computes the context itself and signs nothing else. A submitter cannot redirect the token,
and an app that signs arbitrary data cannot claim, because its CDHash is not under the pinned build.

The NFT pins `build` at deployment. If the registry's owner later approves a different build, keys
from copies of this one still claim here, and copies of the new one do not.

## Run it (Mac with Apple silicon, macOS 27, Full Security)

`deployment.json` holds the Base Sepolia addresses. Build and sign a copy (below), register it, then:

```sh
open -n -W AttestNFT.app --args enroll "$PWD/key"
cast send $VERIFIER $(python3 calldata.py enroll key $INTERMEDIATE) --rpc-url $RPC --account me
open -n -W AttestNFT.app --args claim "$PWD/key" 84532 $NFT $YOUR_ADDRESS   # reads the chip
cast send $NFT $(python3 calldata.py claim key) --rpc-url $RPC --account me
```

`INTERMEDIATE` is the Apple intermediate's entry in `AppleEndorsements`,
`0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90`. If enrollment reverts with
`intermediate validity`, Apple has rotated its intermediate: endorse the new one first
([app-attest/DEPLOY.md](../../app-attest/DEPLOY.md)). Enrollment costs about 14M gas because it
verifies Apple's P-384 certificate signature in Solidity; a claim costs about 250k.

## Sign your own copy

You need a paid Apple Developer team, a Developer ID Application certificate, and a provisioning
profile for an App ID with the App Attest capability. Re-sign the released executable unchanged:

```sh
./build.sh "Developer ID Application: You (TEAMID)" you.provisionprofile TEAMID com.you.attestnft approved/attest-nft
python3 ../../contracts/cd_args.py build/AttestNFT.app/Contents/MacOS/attest-nft > mine.json
b(){ python3 -c "import json,sys;print(json.load(open('mine.json'))[sys.argv[1]])" $1; }
cast send $CDS 'registerBuild(bytes,bytes,bytes)' $(b cd) $(b page0) $(b ent) --rpc-url $RPC --account me
```

Then run the enroll and claim steps with your copy. Your team ID, bundle ID and signature differ
from the deployer's; the registry admits the copy because the code, entitlement keys and
CodeDirectory flags match. Omit the last argument to `build.sh` to compile `App.swift` yourself:
the code pages match only with the approved build's toolchain (Swift 6.4.2, `-O`, macOS 27 SDK, arm64).

## Deploy your own

```sh
python3 ../../contracts/cd_args.py build/AttestNFT.app/Contents/MacOS/attest-nft > build/approved.json
BUILD=build/approved.json forge script script/Deploy.s.sol --rpc-url $RPC --account deployer --broadcast
forge test
```

## Base Sepolia, 2026-11-24

Approved build: `approved/attest-nft`, compiled on a Mac mini (M4 Pro), signed Apple Development
`DC9JH5DRMY`, CDHash `0xb24b66b469072ab69ded9094e26c032c71535b0eae8c726bf31ea11d271d00b8`.

| Contract | Address | Tx |
|---|---|---|
| CDRegistry | `0xB0151C7e78f1411985BB42F22d1Bd4024FA3d7aD` | `0xd94c8df98a229c979b2e4fddeb1294d676b08b77abd91c1aceee39a05eaab98d` |
| AppleAttestAnyBuildV1 (`registry` = AttestNFT) | `0xc1B50B82A3B115e07910cd808a0F2a6b9C710c07` | `0x626116e88d25c010efc21b866e3eb96158c71e9f2c4002287907be34d847615d` |
| AttestNFT | `0x26497625222196288F77AFDa440f13502A70334a` | `0x7d5332dd6e639417e1e8f0232a3212e36627fee84ad338e2ad487cd55a76e6f4` |

The mini enrolled key `0x8a010228…fa6b` in `0x6a6ebc12e0f42728dfbceb9f1bcc8807eff37d616dcf686e02ff5ab332af77ee`
(13,886,275 gas) and claimed token `0x4bb94217…fce0` ("Apple M4 Pro", chip-id `0x6040`) to `0x9788…E6aA` in
`0xc70130372e8ea7133cb7501db9339ef42199e6a3b34a37a6aeed70545febf7b9` (337,816 gas).

The notarized Developer ID copy in the `attest-nft-v1` release (CDHash
`0x6b5053c08de171db34d51eeab0c55a0d69936f5b8e7ec0866f993f1942391ae1`) was registered as a copy of that build in
`0x8db1f5ecf30468681af96d542545ceb3225cadda146ad48c4e005a9e51ac7952`.
