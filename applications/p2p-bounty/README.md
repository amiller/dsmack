# P2P bounty

A bounty that pays on Base with no server in the loop. The `Bounty` contract
(`contracts/src/Bounty.sol`) pays an entry to the first payee named by a guest Attest from
a pinned checker workload. The checker runs on the claimant's own Mac inside a dsmack guest,
and calls `/v1/Attest` only after the bounty's fixed test passes on the candidate commit, with
`report_data = sha256("dsmack.bounty.claim/1" ‖ chainid ‖ bounty ‖ id ‖ payee ‖ commit) ‖ 0^32`.
The contract verifies that assertion through an App Attest verifier bound to it, checks that the
runner copy is registered in CDRegistry under the entry's build, and pays the payee.

Entry 0 is issue #98: `Workspaces.remote()` must turn an unreachable snapshot store into
`WORKSPACE_STORE_UNAVAILABLE` / 503 ([check-98.mjs](check-98.mjs)).

| | |
|---|---|
| Workload | `bounty-98-v1`, node:24.15.0-bookworm-slim (arm64), manifest `fe9bd9f30b8e0b9d65d8f70c86e0658f47266f86bfdec3bdbec6c4f463b87536` |
| Guest image | `8783a3bea61a43f48b5b625667ca49784975b0e8d908d4d3b0890d0867bf6030` (runner alpha.3) |
| Runner build | CDRegistry build of `0c3d3c90`; the Developer ID alpha.3 copy `b98b6aba` is registered |
| Base commit | `260ac93fb247d057829e033bac24d33ecf9dd2c7` |

## Files

- `check-98.mjs`: the test. Base fails it; a fix passes.
- `driver.mjs`: the guest side. Reads the request from the host, checks every file against
  pinned hashes and the candidate file against the git objects under `commit`, runs the test,
  and attests on pass.
- `inputs.py`: builds the request (git objects for the candidate, base files, ethers.js).
- `workload.py`: builds the compose manifest and `workload.img` (Linux).
- `run.py`: runs the checker on your Mac and saves `result.json`.
- `claim.py`: turns a passing `result.json` into `Bounty.claim` calldata.
- `contracts/script/bounty-launch.sh`: deploys the stack and posts an entry.

## Claim

You need an Apple-silicon Mac on macOS 27, the runner alpha.3 zip (`DsmackRunner.app`, the
guest image, disk templates and `gvproxy`), this bounty's `workload.img`,
`compose-manifest.json` and `ethers.js`, Foundry and a little Base ETH for gas.

1. Fix #98 on a branch of this repository and commit.
2. Enroll the runner's App Attest key with the bounty's verifier (~14.3M gas):

   ```sh
   head -c 32 /dev/urandom > challenge.bin
   open -n -W DsmackRunner.app --args enroll $PWD/enrollment $PWD/challenge.bin
   read LEAF AUTH < <(PYTHONPATH=$DSMACK python3 -c "import sys;from verifier.core import decode;a=decode(open(sys.argv[1],'rb').read());print('0x'+a['attStmt']['x5c'][0].hex(),'0x'+a['authData'].hex())" enrollment/attestation.cbor)
   cast send $VERIFIER 'enroll(bytes,bytes,bytes,bytes32)' $LEAF $AUTH 0x$(xxd -p enrollment/clientData.bin | tr -d '\n') \
     0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90 --gas-limit 16000000 --rpc-url $RPC --account $ACCOUNT
   ```

   If you re-sign the runner under your own team, `registerBuild` it on the CDRegistry first.
3. Build the request and run the checker. `runner/` holds `DsmackRunner.app`, `base/`,
   `runtime/base/*-template.ext4`, `runtime/helper/gvproxy-darwin` and `enrollment/`; `run/`
   holds `workload.img` and `compose-manifest.json`:

   ```sh
   python3 -c "import json,inputs;print(json.dumps(inputs.request('$DSMACK','260ac93fb247d057829e033bac24d33ecf9dd2c7','<your commit>','<payee>',8453,'$BOUNTY',0,'ethers.js')))" > request.json
   python3 run.py runner run request.json
   ```

   It prints `"passed": true` when the test passed and the guest attested.
4. Claim from any account; the payout goes to the payee in the attestation:

   ```sh
   cast send $BOUNTY $(python3 claim.py run/result.json 0) --rpc-url $RPC --account $ACCOUNT
   ```
