#!/usr/bin/env python3
"""Replace a paused test network's code baseline with the final signed release.

PRIVATE_KEY is read only from the environment. Public transaction hashes are
saved before submission. A pre-existing journal must be reconciled manually;
this command never blindly resumes or activates a network.
"""
import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rpc', required=True)
    p.add_argument('--deployment', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if args.out.exists():
        raise SystemExit('Journal exists: reconcile its transaction hashes before proceeding')
    deployment = json.loads(args.deployment.read_text())
    build = json.loads(args.build.read_text())
    w = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={'timeout': 120}))
    if w.eth.chain_id not in (31337, 84532) or w.eth.chain_id != deployment['chainId']:
        raise SystemExit('Wrong test network')
    account = Account.from_key(os.environ['PRIVATE_KEY'])
    if account.address != deployment['admin']:
        raise SystemExit('Wrong release administrator')

    def contract(field, name):
        artifact = json.loads((ROOT / f'contracts/out/{name}.sol/{name}.json').read_text())
        return w.eth.contract(address=deployment[field], abi=artifact['abi'])

    network = contract('DemoV1', 'DemoV2')
    registry = contract('macCDRegistry', 'CDRegistry')
    if not network.functions.paused().call():
        raise SystemExit('Network must be paused before changing its release baseline')
    evidence = [bytes.fromhex(build[k].removeprefix('0x')) for k in ('cd', 'page0', 'ent')]
    cdhash = hashlib.sha256(evidence[0]).digest()
    if cdhash.hex() != build['cdhash'].removeprefix('0x'):
        raise SystemExit('CodeDirectory hash mismatch')
    record = {'chainId': w.eth.chain_id, 'registry': network.address,
              'codeRegistry': registry.address, 'cdhash': build['cdhash'], 'transactions': []}

    def save():
        args.out.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.out.with_suffix('.tmp')
        tmp.write_text(json.dumps(record, indent=2) + '\n')
        tmp.replace(args.out)

    def send(function, action):
        gas = function.estimate_gas({'from': account.address})
        if w.eth.chain_id == 84532 and gas > 16_000_000:
            raise SystemExit('Transaction exceeds Base gas cap')
        tx = function.build_transaction({
            'from': account.address,
            'nonce': w.eth.get_transaction_count(account.address, 'pending'),
            'gas': min(gas + gas // 5, 16_000_000) if w.eth.chain_id == 84532 else gas * 2,
            'gasPrice': w.eth.gas_price * 2})
        signed = account.sign_transaction(tx)
        entry = {'action': action, 'hash': signed.hash.to_0x_hex(),
                 'nonce': tx['nonce'], 'status': 'prepared'}
        record['transactions'].append(entry)
        save()
        w.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w.eth.wait_for_transaction_receipt(signed.hash, timeout=180)
        entry['status'] = 'confirmed' if receipt['status'] == 1 else 'reverted'
        save()
        if receipt['status'] != 1:
            raise SystemExit('Admission transaction reverted')
        if w.eth.chain_id == 84532:
            time.sleep(4)

    send(registry.functions.setBuild(*evidence, build['linkeditCmd'], build['codeSigCmd']),
         'set final signed release baseline')
    send(registry.functions.registerBuild(*evidence), 'register final signed release')
    assert registry.functions.isAdmitted(cdhash).call()
    assert network.functions.paused().call()
    record.update(admitted=True, paused=True)
    save()
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
