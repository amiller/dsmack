#!/usr/bin/env python3
"""Plan (default) or publish the main artwork collection on the configured testnet.

PRIVATE_KEY is read only with --broadcast. Pause and drain the sponsor relay first.
Keep the journal: it records each exact signed transaction before submission. A
partial run must be reconciled, never blindly retried with a different journal.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request

from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.', text=True)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(name, path)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rpc', default='https://sepolia.base.org')
    p.add_argument('--network', type=Path, required=True)
    p.add_argument('--artworks', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--collection', help='Publish additional receipt artwork to this existing collection')
    p.add_argument('--relay', help='Relay route to check for paused, drained sponsor writes')
    p.add_argument('--broadcast', action='store_true')
    a = p.parse_args()
    network = json.loads(a.network.read_text())
    artworks = json.loads(a.artworks.read_text())
    w3 = Web3(Web3.HTTPProvider(a.rpc, request_kwargs={'timeout': 60}))
    chain = w3.eth.chain_id
    assert chain in (31337, 84532) and chain == network['chainId'], 'wrong/test-only chain'
    admin = Web3.to_checksum_address(network['admin'])
    source = Web3.to_checksum_address(network['ResearchBadges'])
    def artifact(name):
        return json.loads((ROOT / 'contracts/out' / (name + '.sol') / (name + '.json')).read_text())
    original = w3.eth.contract(address=source, abi=artifact('ResearchBadges')['abi'])
    assert original.functions.network().call().lower() == network['DemoV1'].lower(), 'receipt network mismatch'
    assert original.functions.category().call().hex() == network['macCategory'][2:].lower(), 'receipt category mismatch'
    assert original.functions.adapter().call().lower() == network['macAdapter'].lower(), 'receipt adapter mismatch'
    ca = artifact('ResearchCollection')
    factory = w3.eth.contract(abi=ca['abi'], bytecode=ca['bytecode']['object'])
    collection = w3.eth.contract(address=Web3.to_checksum_address(a.collection), abi=ca['abi']) if a.collection else None
    if collection:
        assert collection.functions.receipts().call() == source, 'wrong receipt source'
        assert collection.functions.owner().call() == admin, 'wrong publisher'
    tokens = []
    seen = set()
    for item in artworks:
        tid = int(item['tokenId'])
        assert tid > 0 and tid not in seen, 'invalid/duplicate token'
        seen.add(tid)
        manifest = json.loads((ROOT / item['manifest']).read_text())
        assert manifest['identity'] == f'attest-fold-v1:{chain}:{source.lower()}:{tid}', 'art identity mismatch'
        assert len(bytes.fromhex(manifest['sourceSha256'])) == 32, 'renderer hash'
        uri = item['image']
        assert uri.startswith('https://') and 8 < len(uri) <= 512, 'image URI'
        assert all(33 <= ord(c) <= 126 and c not in '\\"<>' for c in uri), 'image URI characters'
        with urllib.request.urlopen(uri, timeout=60) as r:
            assert r.status == 200
            image = r.read(16 * 1024 * 1024 + 1)
        assert image.startswith(b'\x89PNG\r\n\x1a\n') and len(image) <= 16 * 1024 * 1024, 'image format/size'
        assert hashlib.sha256(image).hexdigest() == manifest['imageSha256'], 'published image hash mismatch'
        tokens.append(dict(tokenId=tid, owner=original.functions.ownerOf(tid).call(), image=uri,
                           imageSHA256='0x' + manifest['imageSha256'], rendererSHA256='0x' + manifest['sourceSha256']))
    assert tokens, 'empty publication'
    plan = dict(chainId=chain, admin=admin, receiptContract=source, ResearchCollection=a.collection,
                bytecodeSHA256=hashlib.sha256(bytes.fromhex(ca['bytecode']['object'].removeprefix('0x'))).hexdigest(),
                tokens=tokens, transactions=[])
    if not a.broadcast:
        print(json.dumps(plan, indent=2))
        return
    journal = a.out.with_suffix('.journal.json')
    assert not a.out.exists() and not journal.exists(), 'existing output/journal: reconcile before retrying'
    account = Account.from_key(os.environ['PRIVATE_KEY'])
    assert account.address == admin, 'wrong publisher key'
    def maintenance():
        if chain == 84532:
            assert a.relay and a.relay.startswith('https://'), 'relay maintenance URL required'
            with urllib.request.urlopen(a.relay.rstrip('/') + '/status', timeout=30) as r:
                status = json.load(r)
            assert status['sponsorWritesPaused'] is True and status['pending'] == [], 'pause and drain relay first'
        # Base RPC may expose a receipt before its latest nonce view catches up.
        deadline = time.monotonic() + 30
        while w3.eth.get_transaction_count(admin, 'latest') != w3.eth.get_transaction_count(admin, 'pending'):
            assert time.monotonic() < deadline, 'pending sponsor nonce; reconcile journal'
            time.sleep(2)
    maintenance()
    atomic_json(journal, plan)
    def send(fn):
        maintenance()
        gas = fn.estimate_gas({'from': admin})
        assert gas + gas // 5 < 16_000_000, 'gas cap'
        tx = fn.build_transaction({
            'from': admin, 'nonce': w3.eth.get_transaction_count(admin, 'pending'),
            'chainId': chain, 'gas': gas + gas // 5, 'gasPrice': w3.eth.gas_price * 2})
        signed = account.sign_transaction(tx)
        entry = dict(hash=signed.hash.to_0x_hex(), raw=signed.raw_transaction.to_0x_hex(),
                     nonce=tx['nonce'], status='prepared')
        plan['transactions'].append(entry)
        atomic_json(journal, plan)
        w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(signed.hash, timeout=180)
        entry.update(status='confirmed' if receipt['status'] == 1 else 'reverted',
                     blockNumber=receipt['blockNumber'], contractAddress=receipt['contractAddress'])
        atomic_json(journal, plan)
        assert receipt['status'] == 1, 'transaction reverted; inspect journal'
        # Allow Base's sequencer/RPC latest-state views to converge before reads.
        if chain == 84532:
            time.sleep(4)
        return receipt
    if not collection:
        address = send(factory.constructor(source, admin))['contractAddress']
        collection = w3.eth.contract(address=address, abi=ca['abi'])
        plan['ResearchCollection'] = address
        atomic_json(journal, plan)
    for token in tokens:
        tid = token['tokenId']
        send(collection.functions.publishArtwork(tid, token['image'], token['imageSHA256'], token['rendererSHA256']))
        send(collection.functions.issueReceipt(tid))
        assert original.functions.ownerOf(tid).call() == token['owner'] == collection.functions.ownerOf(tid).call(), 'owner changed'
        uri = collection.functions.tokenURI(tid).call()
        assert uri.startswith('data:application/json;base64,')
        metadata = json.loads(base64.b64decode(uri.split(',', 1)[1]))
        assert metadata['image'] == token['image'] and metadata['image_sha256'] == token['imageSHA256']
        assert metadata['receipt_contract'].lower() == source.lower() and metadata['receipt_token'] == tid
        token['metadata'] = metadata
        token['explorer'] = f'https://sepolia.basescan.org/token/{collection.address}?a={tid}'
        atomic_json(journal, plan)
    plan['verifiedBlock'] = w3.eth.block_number
    public = {**plan, 'transactions': [{k:v for k,v in t.items() if k != 'raw'} for t in plan['transactions']]}
    atomic_json(a.out, public)
    print(json.dumps(public, indent=2))


if __name__ == '__main__':
    main()
