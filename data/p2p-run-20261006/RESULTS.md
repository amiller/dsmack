# Two-node App Attest network run, 2026-10-06

Two macOS 27 processes on the Mac mini (M4 Pro, macOS 27.0 26A428, Xcode 27), real `DCAppAttestService`, launched with `open -n` (a binary exec'd directly from ssh reports `isSupported == false`). Peers exchange HELLO/PARCEL/PROOF through the relay mailbox (`node/relay/relay.py`, laptop, reached from the mini over `ssh -R`). The relay pays gas and is `Request.owner`. It never sees a group key. Driver: `node/run_p2p.py`. Same driver, same builds, on anvil (`anvil/`) and on Base Sepolia (`base-sepolia/`). Every check passed on both chains.

## Builds (`builds/`)

| Build | How | CDHash (SHA-256 CD) |
|---|---|---|
| honest (node A) | `node/mac/build.sh honest`, Apple Development DC9JH5DRMY, `--timestamp=none` | `b3e43fb8…8e94` |
| resigned (node B) | `ditto` of honest + `codesign --force --signature-size 20000` (same code, only LC_CODE_SIGNATURE datasize in page 0 differs) | `d2c7d778…3b29` |
| modified | `-D MODIFIED` (different string constant) | `5cf94f0b…c78a` |

`scripts/cross_signer.py`: resigned differs from honest in code slot 0 only, 4 bytes, all inside the mask. Modified differs in slots 0–10.

## Base Sepolia (chain 84532)

Deployer and admin `0x97883cb4B2f21530277F86490d8881654E36E6aA` (owner of DemoV1 and both CDRegistries, not renounced). All 7 contracts are source-verified on Basescan. The two adapters were verified with `scripts/verify_standard_json.py`, because `forge verify-contract` failed with "bytecode does NOT match" (explained below).

| Contract | Address |
|---|---|
| DemoV1 | `0x0505b620b4557235dBD05ee2cc8D25C52d958fB1` |
| macOS CDRegistry (approved = honest) | `0x266eB9D201170dA1acb9CdB96B7A6a3e1A8f880d` |
| macOS AppleAttestRegistryV1 (category 3, Mac ACL) | `0x7d55E98058CaCF7579606eE4a5Ed865B81c5e8E8` |
| iOS CDRegistry (approved = 09-23 iPhone build `5395bf39…`) | `0x898a453Df25d27b57fE9872310C16Dd5A3d726D2` |
| iOS AppleAttestRegistryV1 (category 5, iOS ACL) | `0x105dd06DDf914C372505fACAe09243c1F9A58681` |
| DemoTokenV1 / MembershipReceiptV1 | `0xd9D46a88D61AcE601924a531Fc0D3DDbB0bBE154` / `0x6EFcEA076598fA6B042F152aBFd44938FA9A75E7` |

The 14 deploy transactions are in `base-sepolia/deploy-broadcast.json` (forge broadcast) and the addresses in `base-sepolia/deploy-base-sepolia.json`.

Run (`base-sepolia/{driver.jsonl,relay.jsonl,*.log}`). The attested CDHashes were decoded from the on-chain `enroll` calldata (`base-sepolia/enroll-cdhashes.txt`).

| Step | Node | Tx | Gas | Outcome |
|---|---|---|---|---|
| A enroll (honest, CDHash `b3e43fb8…`) | a | `0x16ba6003…a82a` | 14,319,391 | Enrolled |
| A bootstrap overall group key | a | `0x3dadf30d…2641` | 328,523 | Bootstrapped |
| B enroll before registerBuild | b-unregistered | reverted (estimate) | | `build not admitted` |
| registerBuild(resigned CD, page 0, entitlements) | driver | `0xddfe9c58…6eb2` | 597,560 | admitted, rpIdHash `90a07dc6…` |
| B enroll (resigned, CDHash `d2c7d778…`) | b | `0x028bbaeb…a63c` | 14,407,308 | Enrolled |
| B join (Checked, sessionKeyHash) | b | `0xd4516a16…0f42` | 211,311 | HELLO → A |
| A checks B's Checked ≤60 s + session binding, export (KeyReceipt) | a | `0x2341b7cb…c138` | 173,183 | PARCEL → B |
| B validates A's KeyReceipt, decrypts, import (KeyReceipt) | b | `0xd8180653…f11b` | 173,183 | PROOF → A, A logs `peer holds group key` |
| registerBuild(modified) | driver | reverted (estimate) | | `code slots` |
| modified node enroll | m | reverted (estimate) | | `build not admitted` |
| stale: B' enroll + join, HELLO sent 65 s later | b-stale | `0xccf8d34e…0dc3`, `0x73bd14e8…862b` | | A: `stale peer check-in`, ERROR → B' |
| replay: fresh B'' enroll + join, relay re-delivers B's PARCEL | b-replay | `0xa88bcaee…c9ee`, `0xc81f8d5a…70f1` | | B'': `parcel recipient` (refused before any decryption) |

## Anvil (`anvil/`)

`node/anvil_up.sh`: anvil 1.6.0-nightly `--hardfork osaka` (native P-256 at `0x100`, EIP-7951), deploy, relay with `--settle 0`. The same checks passed (`anvil/driver.jsonl` ends with `all checks passed`).

## iOS simulator (`ios-sim/`)

`node/ios/build_sim.sh` builds the SwiftUI shell over `node/shared`. It ran on an iPhone 17 simulator (iOS 26.5 runtime, the only one installed) against the anvil deploy + relay. The shell read `eth_chainId` and relay `/info`. Then:
- `DCAppAttestService.shared.isSupported == false`, so the node stops with `App Attest unsupported`.
- A direct `generateKey` returns `Error Domain=com.apple.devicecheck.error Code=1` (featureUnsupported).

No attestation was produced or faked. `ios-sim.png` is the screen.

## Findings during the run

- Earlier `forge script` hang (edge-tee worktree, anvil 18545): the Mac `registerBuild` tx had a 464,305 gas limit, below its EIP-7623 calldata floor of 587,130 (dense page 0). Anvil kept it unmined, and forge waited for its receipt. Reproduced on 18555. Fixed by deploying with `--gas-estimate-multiplier 200`.
- `forge verify-contract` cannot reproduce the adapters: via-IR output for `AppleAttestRegistryV1` depends on the compilation unit (19,744 bytes compiled alone vs 19,885 bytes in forge's full unit, which is what was deployed). Verifying with the full unit's sources passes.
- Public Base Sepolia RPC lags the sequencer. The first attempt (`base-sepolia/attempt1/`) reverted `key validity` 0.4 s after the enroll receipt. The relay now waits `--settle 4` s after each receipt.
- App Attest assertion clientDataHash must be the 32-byte request context itself (the adapter computes `sha256(auth ‖ context)`). Enrollment passes `sha256(clientData)`.

## Not tested

iOS App Attest on a device (no iOS 27 phone). iOS admission is covered only by the on-chain replay of papi's 09-23 captures in `contracts/test`. All three nodes ran on one Mac (one physical device). The relay is trusted for liveness and message delivery only.
