# Claiming a dsmack canary

The canary contract on Base Sepolia (chain 84532) holds entries that pay the first proof
that a dsmack isolation boundary broke. Every entry is bound to the approved runner build.

```sh
cast wallet import claimer --interactive   # once: store your key in a foundry keystore
ACCOUNT=claimer
RPC=https://sepolia.base.org
CDS=0xD6567Da581BCcA8Ce965cD16785a43acbf3378f6
VERIFIER=0x08351Cf4B691721fF8F2D7d737E41Eb2FD2c0fD9
CANARY=0x93942C82Aef24C596A90C447f5AfAF083abF926F
CLAIMANT=0xYourAddress
cast call $CANARY 'entries(uint256)(uint8,bytes32,bytes32,bytes32,address,uint64,uint256,bool)' 0 --rpc-url $RPC
```

An entry's fields are kind (0 Forgery, 1 Guest, 2 Runner, 3 Owner), build, image, manifest,
funder, until, amount, burned. Armed entries, each 0.01 ETH until 2027-01-24:

| id | kind | boundary | binds |
|---|---|---|---|
| 0 | Forgery | App Attest / CDRegistry / verifier | build |
| 1 | Runner | guest → runner process | build, any image |
| 2 | Guest | workload → guest root | build, this image |
| 3 | Owner | Mac owner → guest memory | build, this image, the canary manifest |

This release's image and manifest are

- `os_image_hash` `3bec88cae3271ce70661c55c8f0a0cf13b98700a3dcb8d45199d1af8329cdce7`
- canary compose manifest sha256 `ab59dfd00d28a6ba430ec8610068dc853514c99e1b866e94aa9af00f40cd6115`

| Kind | Key to recover | Boundary |
|---|---|---|
| Guest | `canary-guest-key`, in the guest's root tmpfs | a workload of your choice on this image reaches guest root |
| Owner | `canary-guest-key`, with the canary workload | the Mac's owner reads the guest |
| Runner | `canary-runner-key`, in the app's memory | anyone reads the runner app's memory |
| Forgery | none | an App Attest assertion the app never makes |

Commands run in the directory holding this release's files, with Foundry's `cast` and the
checkout and Python set up as in RUNNER-README.md (`DSMACK` is the checkout, `PY` its venv's
`python`).

## 1. Re-sign the runner and enroll its App Attest key

Re-sign `dsmack-runner` for your Mac and register it with `registerBuild`; see
RUNNER-README.md. Then create an App Attest key and enroll it with the canary verifier
(about 14.1M gas; it reverts with `build not admitted` until your
`registerBuild` is mined):

```sh
head -c 32 /dev/urandom > challenge.bin
open -n -W DsmackRunner.app --args enroll $PWD/enroll $PWD/challenge.bin
read LEAF AUTH < <(PYTHONPATH=$DSMACK $PY -c "import sys;from verifier.core import decode;a=decode(open(sys.argv[1],'rb').read());print('0x'+a['attStmt']['x5c'][0].hex(),'0x'+a['authData'].hex())" enroll/attestation.cbor)
cast send $VERIFIER 'enroll(bytes,bytes,bytes,bytes32)' $LEAF $AUTH 0x$(xxd -p enroll/clientData.bin | tr -d '\n') \
  0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90 --gas-limit 16000000 --rpc-url $RPC --account $ACCOUNT
```

## 2. Run the canary workload

Put this release's files in one directory and unpack the disk templates.
`canary-v1-oci-layout.tar` is the workload's container image for inspection; the run does not
need it.

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS
gunzip -k scratch-template.ext4.gz result-template.ext4.gz
curl -LO https://github.com/containers/gvisor-tap-vsock/releases/download/v0.8.9/gvproxy-darwin
echo 'c6f7b4bc7f21bf810b5cf54e04d979b014c5d96472a03a9e97fe62a00940067c  gvproxy-darwin' | shasum -a 256 -c && chmod 755 gvproxy-darwin
python3 run-canary.py $PWD $PWD/DsmackRunner.app enroll/keyId.txt $PWD/gvproxy-darwin run-1
$(brew --prefix e2fsprogs)/sbin/debugfs -R 'dump /canary-v1/outputs/artifacts/attestation run-1/attestation.json' run-1/out/result.img
python3 -c "import json;print(json.load(open('run-1/attestation.json'))['attestation'])" > run-1/attestation.hex
```

`debugfs` comes from `brew install e2fsprogs`. The run takes about ten minutes;
the workload calls `/v1/Attest` and then sleeps, so the keys are live during the sleep.
For a Guest entry, write your own compose for this image with `canary_workload.py` as the
template; your workload must call `/v1/Attest` itself.

## 3. Claim a key entry

Break the boundary and recover the 32-byte P-256 scalar of the entry's key. Its public key
is the `canary-guest-key` or `canary-runner-key` event in the attestation. Then:

```sh
ID=2   # 1 Runner, 2 Guest, 3 Owner
$PY $DSMACK/contracts/canary_claim.py $(cat run-1/attestation.hex) <key hex> $CLAIMANT $ID $CANARY 84532 > claim.json
cast call $CANARY $(python3 -c "import json;print(json.load(open('claim.json'))['calldata'])") --rpc-url $RPC
cast send $CANARY $(python3 -c "import json;print(json.load(open('claim.json'))['calldata'])") --rpc-url $RPC --account $ACCOUNT
```

Assertions by one key are accepted in counter order. Claim with the Attest assertion
before submitting any later assertion by the same key.

## 4. Claim the Forgery entry

Produce an assertion by your enrolled key over `clientDataHash = forgeryContext(0, CLAIMANT)`.
The app only asserts over its own fixed domains, so this needs the key outside the app.

```sh
cast call $CANARY 'forgeryContext(uint256,address)(bytes32)' 0 $CLAIMANT --rpc-url $RPC
# assertion.cbor: the forged App Attest assertion over that 32-byte value
PROOF=$(PYTHONPATH=$DSMACK $PY - <<'EOF'
import base64
from verifier.core import decode
from eth_abi import encode
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
m = decode(open('assertion.cbor', 'rb').read()); r, s = decode_dss_signature(m['signature'])
kid = base64.b64decode(open('enroll/keyId.txt').read())
print('0x' + encode(['bytes32', 'bytes', 'uint256', 'uint256'], [kid, m['authenticatorData'], r, s]).hex())
EOF
)
cast send $CANARY 'claimForgery(uint256,address,bytes)' 0 $CLAIMANT $PROOF --rpc-url $RPC --account $ACCOUNT
```

A claimed entry stays burned on chain as public evidence of the break.
