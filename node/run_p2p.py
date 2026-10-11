"""Live two-node run on the Mac mini (ssh alias mini-mesh) plus negative controls.
Laptop side; needs the relay running and reachable from the mini at --relay, the chain at --rpc-mini,
and PRIVATE_KEY in the environment (sends registerBuild). Node logs land in <out>/<name>.log."""
import argparse, json, os, subprocess, time, urllib.request
from pathlib import Path
from web3 import Web3
from eth_account import Account

ap = argparse.ArgumentParser()
ap.add_argument('--deploy', required=True); ap.add_argument('--rpc', required=True)
ap.add_argument('--rpc-mini', required=True); ap.add_argument('--relay', required=True)
ap.add_argument('--relay-log', required=True); ap.add_argument('--out', required=True); ap.add_argument('--builds', required=True)
ap.add_argument('--settle', type=float, required=True)
args = ap.parse_args()
out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
deploy = json.loads(Path(args.deploy).read_text())
w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={'timeout': 60})); account = Account.from_key(os.environ['PRIVATE_KEY'])
contracts = Path(args.deploy).resolve().parents[1]
cds = w3.eth.contract(address=deploy['macCDRegistry'], abi=json.loads((contracts/deploy['CDRegistryArtifact']).read_text())['abi'])
REMOTE = 'apple-attest-p2p/run'
APPS = {v: f'apple-attest-p2p/node/mac/build/{v}/Node.app' for v in ('honest', 'resigned', 'modified')}

def note(**e):
    print(json.dumps(e), flush=True)
    with open(out/'driver.jsonl', 'a') as f: f.write(json.dumps({'t': time.time(), **e}) + '\n')

def ssh(cmd, **kw): return subprocess.run(['ssh', 'mini-mesh', cmd], check=True, text=True, capture_output=True, **kw).stdout

def launch(name, variant, role, **extra):
    cfg = {'rpc': args.rpc_mini, 'registry': deploy['DemoV1'], 'chainId': w3.eth.chain_id, 'category': deploy['macCategory'],
           'relay': args.relay, 'name': name, **extra}
    ssh(f'mkdir -p {REMOTE} && cat > {REMOTE}/{name}.json && rm -f {REMOTE}/{name}.log', input=json.dumps(cfg))
    ssh(f'cd ~/{REMOTE} && (open -n -W --stdout $PWD/{name}.log --stderr $PWD/{name}.log ~/{APPS[variant]} --args $PWD/{name}.json {role} >/dev/null 2>&1 &)')
    note(launched=name, variant=variant, role=role, config=cfg)

def events(name):
    text = ssh(f'cat {REMOTE}/{name}.log 2>/dev/null || true')
    (out/f'{name}.log').write_text(text)
    return [json.loads(l) for l in text.splitlines() if l.startswith('{')]

def wait(name, event, timeout=240):
    end = time.time() + timeout
    while time.time() < end:
        for e in events(name):
            if e['event'] == event or (e['event'] == 'error' and event != 'error'): return e
        time.sleep(2)
    raise TimeoutError(f'{name}: no {event}')

def expect(name, event, contains=None, timeout=240):
    e = wait(name, event, timeout)
    assert e['event'] == event and (contains is None or contains in json.dumps(e)), (name, event, contains, e)
    note(check=f'{name} {event}', ok=True, detail=e)
    return e

def send(fn, label):
    tx = fn.build_transaction({'from': account.address, 'nonce': w3.eth.get_transaction_count(account.address, 'pending'),
                               'gas': int(fn.estimate_gas({'from': account.address}) * 1.5), 'gasPrice': w3.eth.gas_price * 2})
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction), timeout=120)
    assert receipt['status'] == 1, label
    time.sleep(args.settle)
    note(tx=label, hash=receipt['transactionHash'].to_0x_hex(), gasUsed=receipt['gasUsed'])

def build_args(variant):
    j = json.loads((Path(args.builds)/variant/'cd-args.json').read_text())
    return j['cdhash'], [bytes.fromhex(j[k][2:]) for k in ('cd', 'page0', 'ent')]

def relay(path, body):  # the mini-side relay URL also works here: the ssh -R tunnel uses the same port
    req = urllib.request.Request(args.relay + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req).read())

# 1. Node A: approved build, enrolls, bootstraps the overall group key, listens.
launch('a', 'honest', 'listen')
expect('a', 'executed')
# 2. Node B on the re-signed copy before registerBuild: rejected at enrollment.
resigned, resigned_args = build_args('resigned')
assert not cds.functions.isAdmitted(bytes.fromhex(resigned[2:])).call()
launch('b-unregistered', 'resigned', 'connect', peer='a')
expect('b-unregistered', 'error', 'build not admitted')
# 3. Anyone registers the re-signed CodeDirectory; B is then admitted and receives the key from A.
send(cds.functions.registerBuild(*resigned_args), 'registerBuild(resigned)')
assert cds.functions.isAdmitted(bytes.fromhex(resigned[2:])).call()
launch('b', 'resigned', 'connect', peer='a')
expect('b', 'done')
expect('a', 'peer holds group key')
# 4. Modified code: registerBuild reverts, and the node is rejected at enrollment.
modified, modified_args = build_args('modified')
try: cds.functions.registerBuild(*modified_args).estimate_gas({'from': account.address}); raise AssertionError('modified build registered')
except Exception as e: assert 'code slots' in str(e), e; note(check='registerBuild(modified) reverts', ok=True, detail=str(e))
launch('m', 'modified', 'connect', peer='a')
expect('m', 'error', 'build not admitted')
# 5. Stale check-in: HELLO sent 65 s after the join; A refuses, B gets ERROR.
launch('b-stale', 'resigned', 'connect', peer='a', helloDelay=65.0)
expect('b-stale', 'error', 'stale peer check-in', timeout=400)
expect('a', 'refused', 'stale peer check-in')
# 6. Replay: the relay re-delivers B's PARCEL to a fresh process; it refuses before decrypting.
parcel = next(json.loads(l)['message'] for l in open(args.relay_log) if '"PARCEL"' in l)
launch('b-replay', 'resigned', 'connect')
expect('b-replay', 'executed')
relay('/send/b-replay', parcel)
expect('b-replay', 'error', 'parcel recipient')
relay('/send/a', {'type': 'STOP', 'from': 'driver'})
expect('a', 'done')
note(result='all checks passed')
