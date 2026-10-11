"""Untrusted relay: gas sponsor and peer mailbox. It is Request.owner (signs memberSignature with
PRIVATE_KEY from the environment) and submits enroll/execute transactions. It sees requests,
assertions and sealed parcels, never a group key. Reverts come back as HTTP 500 with the reason."""
import argparse, base64, json, os, sys, time
from collections import defaultdict, deque
from pathlib import Path
from flask import Flask, request, jsonify
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_abi import encode
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from verifier.core import decode

ap = argparse.ArgumentParser()
ap.add_argument('--rpc', required=True); ap.add_argument('--deploy', required=True)
ap.add_argument('--port', type=int, required=True); ap.add_argument('--log', required=True)
ap.add_argument('--settle', type=float, required=True, help='seconds to wait after a receipt (public RPC backends lag the sequencer)')
args = ap.parse_args()
w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={'timeout': 60}))
account = Account.from_key(os.environ['PRIVATE_KEY'])
deploy = json.loads(Path(args.deploy).read_text())
contracts_dir = Path(args.deploy).resolve().parents[1]
abi = lambda key: json.loads((contracts_dir/deploy[key]).read_text())['abi']
demo = w3.eth.contract(address=deploy['DemoV1'], abi=abi('DemoV1Artifact'))
boxes = defaultdict(deque)
app = Flask(__name__)

def record(**entry):
    with open(args.log, 'a') as f: f.write(json.dumps({'t': time.time(), **entry}) + '\n')

def send(fn, label):
    gas = fn.estimate_gas({'from': account.address})
    tx = fn.build_transaction({'from': account.address, 'nonce': w3.eth.get_transaction_count(account.address, 'pending'),
                               'gas': gas + gas // 10, 'gasPrice': w3.eth.gas_price * 2})
    txid = w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(txid, timeout=120)
    assert receipt['status'] == 1, f'{label} reverted on chain'
    time.sleep(args.settle)
    record(kind='tx', label=label, tx=txid.to_0x_hex(), block=receipt['blockNumber'], gasUsed=receipt['gasUsed'])
    return txid.to_0x_hex()

def request_tuple(r):
    b = lambda k: bytes.fromhex(r[k].removeprefix('0x'))
    n = lambda k: int(r[k], 16) if isinstance(r[k], str) else int(r[k])
    return (n('action'), b('category'), r['owner'], r['memberSigner'], b('sessionKeyHash'), n('nonce'), n('validUntil'),
            b('scope'), n('keyX'), n('keyY'), b('envelopeDigest'))

@app.errorhandler(Exception)
def failed(e):
    record(kind='error', path=request.path, error=str(e))
    return jsonify(error=str(e)), 500

@app.get('/info')
def info(): return jsonify(owner=account.address, chainId=w3.eth.chain_id)

@app.post('/enroll')
def enroll():
    j = request.get_json()
    adapter = w3.eth.contract(address=demo.functions.categories(bytes.fromhex(j['category'][2:])).call()[0], abi=abi('AdapterArtifact'))
    att = decode(base64.b64decode(j['attestation']))
    fn = adapter.functions.enroll(att['attStmt']['x5c'][0], att['authData'], bytes.fromhex(j['clientData'][2:]))
    return jsonify(tx=send(fn, 'enroll'))

@app.post('/execute')
def execute():
    j = request.get_json(); r = request_tuple(j['request'])
    context = demo.functions.contextHash(r).call()
    assert context.hex() == j['context'].removeprefix('0x'), 'node context differs from contextHash'
    a = decode(base64.b64decode(j['assertion'])); x, y = decode_dss_signature(a['signature'])
    proof = encode(['bytes32', 'bytes', 'uint256', 'uint256'], [base64.b64decode(j['keyId']), a['authenticatorData'], x, y])
    signature = account.sign_message(encode_defunct(primitive=context)).signature
    fn = demo.functions.execute(r, proof, signature, bytes.fromhex(j['groupSignature'].removeprefix('0x')))
    return jsonify(tx=send(fn, ['join', 'claim', 'bootstrap', 'receipt'][r[0]]))

@app.post('/send/<to>')
def post(to):
    m = request.get_json(); boxes[to].append(m); record(kind='message', to=to, message=m)
    return jsonify(queued=len(boxes[to]))

@app.get('/recv/<name>')
def recv(name): return jsonify(message=boxes[name].popleft() if boxes[name] else None)

app.run(host='127.0.0.1', port=args.port, threaded=False)
