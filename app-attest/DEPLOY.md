# Deployment checklist

Before deploying an adapter:

- Record the chain, AppleEndorsements address and `extcodehash` of its deployed
  runtime. Match that runtime to the production `AppleEndorsements` artifact
  built with the recorded compiler settings. Reject test subclasses: `_rootKey`
  is virtual, so a subclass can override the Apple root.
- Check the adapter's endorsement address, policy/registry, platform profile,
  category and ACL, and the deployed verifier and linked ZKTranscriptLib against
  their reviewed artifacts. Record addresses and runtime code hashes.
- Rebuild the leaf circuit with nargo 1.0.0-beta.17 and bb 3.0.3. The VK binary's
  SHA256 must be `c808cbc75a32156fc145f53024033ae5499971203cd835b657d7c6f8c7f72587`;
  `circuit/prove-leaf.sh` checks the VK and generated Solidity against the
  committed copies. Use Foundry 1.8.5; application solc 0.8.21, optimizer
  200/via IR; verifier solc 0.8.27, optimizer 1/no IR.
- Run `./test.sh` and record revision, machine and results.

## Read-only code checks

Run the builds and tests in [CONTRIBUTING.md](../CONTRIBUTING.md) first. Set
`RPC`, `BLOCK`, `ENDORSEMENTS`, `VERIFIER`, `TRANSCRIPT` and adapter addresses
from the deployment record. Pin `BLOCK` for all comparisons. The commands read
state or simulate calls. Run all blocks in the
same Bash shell, from the checkout root, with failure stopping enabled:

```sh
set -euo pipefail
```

AppleEndorsements has no constructor arguments or immutables. Its expected
runtime hash is produced directly from the production artifact. With the pinned
settings above, expected runtime keccak256 is
`0x2adc383e4a8a9cb9f369baa61e342e1331a3e52f24778411a14ff54d985f474d`.
The check pins this value, so a different local artifact fails. The value comes
from the forced full `src` build used for deployment. Runtime bytecode depends on
the compilation unit: with solc 0.8.21/via IR, AppleEndorsements compiled alone
(as `forge inspect` may do) differs from the full build. Read the artifact from
the full build, and source-verify with the same build and compiler settings.

```sh
forge build --force --root app-attest/contracts --offline --use "$SOLC"
runtime=$(python3 -c 'import json; print(json.load(open("app-attest/contracts/out/AppleEndorsements.sol/AppleEndorsements.json"))["deployedBytecode"]["object"])')
expected=$(cast keccak "$runtime")
test "$expected" = 0x2adc383e4a8a9cb9f369baa61e342e1331a3e52f24778411a14ff54d985f474d
actual=$(cast codehash "$ENDORSEMENTS" --rpc-url "$RPC" --block "$BLOCK")
test "$actual" = "$expected"
printf '%s\n' "$expected"
```

For the verifier, link the reviewed library address using the remapped source
name (Foundry 1.8.5 does not link this import with its relative filesystem name).
Keep linked output/cache separate from the unlinked real-proof test artifacts.
The verifier constructor fills immutables despite taking no arguments; simulate
creation to obtain its expected runtime:

```sh
(cd app-attest/contracts/verifier && forge build --force --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27" --out ../../../local-data/deploy/verifier-out --cache-path ../../../local-data/deploy/verifier-cache --libraries "leaf-verifier/HonkVerifierLeaf.sol:ZKTranscriptLib:$TRANSCRIPT")
creation=$(python3 - <<'PYCODE'
import json
p = json.load(open('local-data/deploy/verifier-out/HonkVerifierLeaf.sol/HonkVerifier.json'))
assert not p['bytecode']['linkReferences'], 'verifier is not linked'
code = p['bytecode']['object']
bytes.fromhex(code.removeprefix('0x'))
print(code)
PYCODE
)
runtime=$(cast call --rpc-url "$RPC" --block "$BLOCK" --create "$creation")
expected=$(cast keccak "$runtime")
actual=$(cast codehash "$VERIFIER" --rpc-url "$RPC" --block "$BLOCK")
test "$actual" = "$expected"
printf '%s\n' "$expected"
```

Also compare ZKTranscriptLib's runtime with its unlinked artifact from the
CONTRIBUTING build. Deploy the library from that artifact too: compiling it with
`--libraries` changes its metadata and therefore its runtime hash. Library
runtime embeds its own address in the first PUSH20; substitute it before hashing:

```sh
python3 - "$TRANSCRIPT" <<'PY' > "$TMPDIR/transcript-runtime.hex"
import json, sys
p = 'app-attest/contracts/verifier/out/HonkVerifierLeaf.sol/ZKTranscriptLib.json'
code = json.load(open(p))['deployedBytecode']['object'].removeprefix('0x')
assert code[:2] == '73' and code[2:42] == '0'*40
print('0x' + code[:2] + sys.argv[1].removeprefix('0x') + code[42:])
PY
runtime=$(cat "$TMPDIR/transcript-runtime.hex")
expected=$(cast keccak "$runtime")
actual=$(cast codehash "$TRANSCRIPT" --rpc-url "$RPC" --block "$BLOCK")
test "$actual" = "$expected"
printf '%s\n' "$expected"
```

Adapters contain immutables, so hashing the unpatched deployedBytecode artifact
is insufficient. For each concrete production adapter, set `CONTRACT` to its
fully qualified source:name and `ADAPTER` to its address. Set `REGISTRY`,
`APP_HASH`, `CDHASH`, `AAGUID`, `CATEGORY` and `IOS` from the reviewed policy.
The block binds constructor arguments to the reviewed `ENDORSEMENTS` and
`VERIFIER` addresses. Use the artifacts from the first full build for deployment
and simulation:

```sh
case "$CONTRACT" in
    src/MacAppAttestV1.sol:MacAppAttestV1)
        ARGS=$(cast abi-encode 'constructor(address,address,bytes32,bytes32,bytes16,uint32,bool)' "$ENDORSEMENTS" "$REGISTRY" "$APP_HASH" "$CDHASH" "$AAGUID" "$CATEGORY" "$IOS") ;;
    src/MacAppAttestZKV1.sol:MacAppAttestZKV1)
        ARGS=$(cast abi-encode 'constructor(address,address,bytes32,bytes32,bytes16,uint32,bool,address)' "$ENDORSEMENTS" "$REGISTRY" "$APP_HASH" "$CDHASH" "$AAGUID" "$CATEGORY" "$IOS" "$VERIFIER") ;;
    *) echo "Unsupported adapter: $CONTRACT" >&2; exit 1 ;;
esac
creation=$(python3 - "$CONTRACT" <<'PYCODE'
import json, sys
from pathlib import Path
source, name = sys.argv[1].split(':')
p = Path('app-attest/contracts/out') / Path(source).name / (name + '.json')
print(json.loads(p.read_text())['bytecode']['object'])
PYCODE
)
runtime=$(cast call --rpc-url "$RPC" --block "$BLOCK" --create "${creation}${ARGS#0x}")
expected=$(cast keccak "$runtime")
actual=$(cast codehash "$ADAPTER" --rpc-url "$RPC" --block "$BLOCK")
test "$actual" = "$expected" || { echo "Adapter runtime mismatch: $actual != $expected" >&2; exit 1; }
printf '%s\n' "$expected"
expected=$(cast to-check-sum-address "$ENDORSEMENTS")
actual=$(cast call "$ADAPTER" 'endorsements()(address)' --rpc-url "$RPC" --block "$BLOCK")
test "$actual" = "$expected" || { echo "endorsements() mismatch: $actual != $expected" >&2; exit 1; }
if [[ "$CONTRACT" = src/MacAppAttestZKV1.sol:MacAppAttestZKV1 ]]; then
    expected=$(cast to-check-sum-address "$VERIFIER")
    actual=$(cast call "$ADAPTER" 'leafVerifier()(address)' --rpc-url "$RPC" --block "$BLOCK")
    test "$actual" = "$expected" || { echo "leafVerifier() mismatch: $actual != $expected" >&2; exit 1; }
fi
```

Use `src/MacAppAttestZKV1.sol:MacAppAttestZKV1` for the concrete ZK path.
It has the same fixed appHash/CDHash policy as MacAppAttestV1. Its constructor
takes `(address,address,bytes32,bytes32,bytes16,uint32,bool,address)`, appending
the reviewed verifier address to MacAppAttestV1's arguments. Run the adapter
block for each of these two contracts.
Record complete arguments, linked addresses, expected and observed hashes
with the revision. A failed `test`, simulation or build terminates the shell.

## Base Sepolia (chain 84532), 2026-10-21

Deployer `0x97883cb4B2f21530277F86490d8881654E36E6aA`. All checks above passed
(AppleEndorsements, library, verifier at block 48411314; adapters at 48414947).
All five contracts are source-verified on Basescan from the full-build standard
JSON input (`forge build --force --build-info`).

| Contract | Address | Tx | Gas | Runtime keccak256 |
|---|---|---|---:|---|
| AppleEndorsements | `0xb3263f9b42f42d0f8ccabb7014b2ee189580dd81` | `0x432f2e7e503100951abf97e22325b15ca41d066f90bae498dfa0259b4c8d6f95` | 3,764,330 | `0x2adc383e4a8a9cb9f369baa61e342e1331a3e52f24778411a14ff54d985f474d` |
| ZKTranscriptLib | `0x36c670e2388f97db69d682dc9032d4bf174dc159` | `0xc207a3d8c301a474176b66d8c820623063ddf7fa5b0f3534c2afb14c5578a1bc` | 1,331,348 | `0x2783da3155c8f95168709d19798575e75c54d6d93df0b7d08e92723715a505ef` |
| HonkVerifier | `0x33c3b28e4e6cd8252ab109285ed63506cd0b4751` | `0x992979098ce9015495d721a17f3401c9db5b7e24786de228928bb0f2e0671d6a` | 5,181,137 | `0x9bbf72e480a201b6b5599419065bcef406c7c0158ea7f27a0a9a30767274a9a3` |
| MacAppAttestV1 | `0xdebe397150d0ea1ef8d028092e86f84a63561b9e` | `0x62c32086c98564138e624c736f16021e7a4dd92247f2d4c8e028373fac6ebb61` | 4,412,022 | `0x2ba9b789f94cd2a5a841939da5519c3e256f03f5a0f0aead2cb4b134c5805608` |
| MacAppAttestZKV1 | `0x90bf709de047740806e5fd13f794b4ff230bb310` | `0x447b54457b7997ed693d3cbbbcfd44f2a553124b28e926e3829f3c007a21ea6e` | 5,034,780 | `0x49c8445f097fcbed706d97e16b283112a5c25a2915735f7358b55b2603949dbd` |

`endorseIntermediate(fixtures/apple-intermediate.der)` used 15,141,525 gas in
`0xfe26b371ef135394bb534e353c0eecfcc04d1246bab86b05eb7f90c4a7591cd5`, entry id
`0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90`. Its 1.2x
gas estimate exceeds Base's 2^24 per-transaction cap; send it with
`--gas-limit 16000000`.

Adapter policy: registry is the deployer; appHash
`0x90a07dc69293aa64c279caed89cfebd3fde0ad92b510f752ed45ba829157fff6`
(sha256 of `DC9JH5DRMY.dev.dsmack.provider`); CDHash
`0x67dfc08f0eca771ae2787870ab3bffc7dfb39a7fac4db6b0c087e58c2f488d70` (the
Apple Development probe build of the `real-apple`/`fresh-apple` captures);
aaguid `appattest`; category 3; ios false.

### Live run

A fresh capture on a Mac mini (macOS 27.0, 26A428), saved as
[fixtures/live-apple.json](contracts/fixtures/live-apple.json). One attestation,
enrolled in both adapters, and two assertions (`a1`, `a2`).

| Step | Tx | Gas |
|---|---|---:|
| `enroll` on MacAppAttestV1 | `0x0c1692afa0b7279a6be702e4dd7aec99dea7d954d3ab3890fcad8052b1e71f6a` | 14,245,575 |
| `enrollLeafProof` on MacAppAttestZKV1 | `0x347021500ce09fb9683046de2405e216b047bd77397532a1f5fc5bdc1a7956f2` | 4,498,881 |
| `verify` `a1` on MacAppAttestV1 | `0x7a0604361b3447f32da4d06ac2109a4880bad718c36632dcf8aa31b4347fd636` | 186,290 |
| `verify` `a2` on MacAppAttestZKV1 | `0x58f9baa54d175463e33616196ad2273a57f8e2927330523fe123f01fcbb74adf` | 186,312 |

Key id `0x617beba02959792e93de977dbfed9774adac02fcdff204329d3031a812bb1a62`.
The leaf proof was made on a 12-core Linux box with the pinned VK: 13.9 s,
2.97 GB peak. Replaying `a1` reverts with `assertion replay`.
