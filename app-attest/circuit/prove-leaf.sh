#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh
base=$PWD
mkdir -p proofs/leaf/{mac,iphone,fresh}
python3 - <<'PY'
import json
from pathlib import Path
for name in ('real-apple', 'iphone-apple', 'fresh-apple'):
    f = json.loads(Path('../contracts/fixtures/' + name + '.json').read_text())
    f['intermediate'] = Path('../contracts/fixtures/apple-intermediate.der').read_bytes().hex()
    Path('proofs/leaf/' + name + '.json').write_text(json.dumps(f))
PY
./check-leaf.sh proofs/leaf/real-apple.json > proofs/leaf/warmup.log 2>&1
run="$base/../../tools/attest-build/leaf"
exec 9>"$run/.check.lock"
flock 9
bb write_vk -c "$BB_HOME/crs" -b "$run/target/attest_leaf.json" -t evm -o proofs/leaf/vk > proofs/leaf/vk.log 2>&1
for profile in mac iphone fresh; do
    case $profile in mac) fixture=real-apple;; iphone) fixture=iphone-apple;; fresh) fixture=fresh-apple;; esac
    python3 prepare-leaf.py "proofs/leaf/$fixture.json" --out "$run/leaf/Prover.toml"
    (cd "$run" && nargo execute --package attest_leaf attest_leaf) > "proofs/leaf/$profile/execute.log" 2>&1
    bb prove -k proofs/leaf/vk/vk -c "$BB_HOME/crs" -b "$run/target/attest_leaf.json" -w "$run/target/attest_leaf.gz" -t evm -o "proofs/leaf/$profile" > "proofs/leaf/$profile/prove.log" 2>&1
    bb verify -c "$BB_HOME/crs" -k proofs/leaf/vk/vk -p "proofs/leaf/$profile/proof" -i "proofs/leaf/$profile/public_inputs" -t evm > "proofs/leaf/$profile/verify.log" 2>&1
    python3 - "$profile" "$fixture" <<'PY'
import json, sys
from pathlib import Path
from runpy import run_path
profile, fixture = sys.argv[1:]
expected = run_path('prepare-leaf.py')['prepare'](json.loads(Path('proofs/leaf/' + fixture + '.json').read_text()))['public']
raw = Path('proofs/leaf/' + profile + '/public_inputs').read_bytes()
assert [int.from_bytes(raw[i:i+32], 'big') for i in range(0, len(raw), 32)] == [int(v) for v in expected]
PY
done
cmp proofs/leaf/vk/vk verifier/vk
bb write_solidity_verifier -k proofs/leaf/vk/vk -t evm -o proofs/leaf/HonkVerifierLeaf.sol
sed -i 's/[[:blank:]]*$//' proofs/leaf/HonkVerifierLeaf.sol
cmp proofs/leaf/HonkVerifierLeaf.sol verifier/HonkVerifierLeaf.sol
