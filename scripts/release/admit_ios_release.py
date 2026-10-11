#!/usr/bin/env python3
"""Inspect or set a disabled iPhone category's code baseline without pausing Mac peers.

Defaults to read-only inspection. --execute sends only setBuild/registerBuild;
it never enables a category. Input must describe the operator-reviewed installed
TestFlight executable, not an assumed match to an uploaded IPA. This tool checks
contract policy and code structure, not the provenance of that input. Coordinate
all uses of the administrator key and pause relay sponsor writes before execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]
IOS_ACL = bytes.fromhex('3049a347044530430c023131303d300a0c036f6b64a1030101ff30090c026f61a1030101ff300b0c046f73676ea1030101ff300b0c046f64656ca1030101ff300a0c036f636ba1030101ff')


def inspect(w, ios, mac, build):
    def require(value, message):
        if not value:
            raise ValueError(message)
    def contract(name, address):
        abi = json.loads((ROOT / f'contracts/out/{name}.sol/{name}.json').read_text())['abi']
        return w.eth.contract(address=Web3.to_checksum_address(address), abi=abi)
    require(w.eth.chain_id in (31337, 84532) and w.eth.chain_id == ios['chainId'] == mac['chainId'], 'Wrong test chain')
    require(ios['DemoV1'].lower() == mac['DemoV1'].lower(), 'Different peer networks')
    require(ios['iosCDRegistry'].lower() != mac['macCDRegistry'].lower(), 'iPhone registry aliases Mac registry')
    category = bytes.fromhex(ios['iosCategory'].removeprefix('0x'))
    mac_category = bytes.fromhex(mac['macCategory'].removeprefix('0x'))
    require(len(category) == 32 and category != mac_category, 'Invalid or aliased category')
    network = contract('DemoV2', ios['DemoV1'])
    registry = contract('CDRegistry', ios['iosCDRegistry'])
    mac_registry = contract('CDRegistry', mac['macCDRegistry'])
    adapter = contract('AppleAttestRegistryV1', ios['iosAdapter'])
    admin = Web3.to_checksum_address(ios['admin'])
    require(admin.lower() == mac['admin'].lower() and network.functions.owner().call() == admin and registry.functions.owner().call() == admin, 'Wrong administrator')
    policy = network.functions.categories(category).call()
    require(policy[0] == adapter.address and not policy[-1], 'iPhone category must be disabled and use its declared adapter')
    require(adapter.functions.registry().call() == network.address and adapter.functions.cds().call() == registry.address, 'Wrong iPhone adapter bindings')
    require(adapter.functions.validationCategory().call() == 2 and adapter.functions.aaguid().call() == bytes.fromhex('61707061747465737400000000000000') and adapter.functions.keyACL().call() == Web3.keccak(IOS_ACL), 'Not a production iOS TestFlight policy')
    evidence = [bytes.fromhex(build[k].removeprefix('0x')) for k in ('cd', 'page0', 'ent')]
    digest = hashlib.sha256(evidence[0]).digest()
    require(build.get('cdhash', '0x' + digest.hex()).lower() == '0x' + digest.hex(), 'CodeDirectory hash mismatch')
    # Read-only contract validation of page hashes, DER entitlements and offsets.
    registry.functions.measure(*evidence, build['linkeditCmd'], build['codeSigCmd']).call()
    def snapshot():
        return {'paused': network.functions.paused().call(),
                'macBuildId': Web3.to_hex(mac_registry.functions.buildId().call()),
                'macCategory': [Web3.to_hex(v) if isinstance(v, bytes) else v for v in network.functions.categories(mac_category).call()]}
    return network, registry, category, admin, evidence, digest, snapshot


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rpc', required=True)
    p.add_argument('--ios', type=Path, required=True)
    p.add_argument('--mac', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    if a.out.exists():
        raise SystemExit('Output/journal exists; reconcile it before another run')
    ios, mac, build = (json.loads(f.read_text()) for f in (a.ios, a.mac, a.build))
    w = Web3(Web3.HTTPProvider(a.rpc, request_kwargs={'timeout': 120}))
    network, registry, category, admin, evidence, digest, snapshot = inspect(w, ios, mac, build)
    before = snapshot()
    ios_policy = network.functions.categories(category).call()
    record = {'chainId': w.eth.chain_id, 'network': network.address, 'codeRegistry': registry.address,
              'category': Web3.to_hex(category), 'cdhash': Web3.to_hex(digest), 'before': before,
              'readOnly': not a.execute, 'transactions': [], 'inputProvenanceVerified': False}
    def save():
        a.out.parent.mkdir(parents=True, exist_ok=True)
        tmp = a.out.with_suffix('.tmp'); tmp.write_text(json.dumps(record, indent=2) + '\n'); tmp.replace(a.out)
    if a.execute:
        try:
            account = Account.from_key(os.environ['PRIVATE_KEY'])
        except Exception:
            raise SystemExit('Valid administrator PRIVATE_KEY is required') from None
        if account.address != admin:
            raise SystemExit('Wrong signing administrator')
        for label, fn in [('set iPhone baseline', registry.functions.setBuild(*evidence, build['linkeditCmd'], build['codeSigCmd'])),
                          ('register iPhone build', registry.functions.registerBuild(*evidence))]:
            if snapshot() != before or network.functions.categories(category).call() != ios_policy:
                raise SystemExit('Policy changed during admission; inspect the journal')
            nonce = w.eth.get_transaction_count(admin, 'latest')
            if nonce != w.eth.get_transaction_count(admin, 'pending'):
                raise SystemExit('Administrator has pending transactions; coordinate sponsor writes first')
            gas = fn.estimate_gas({'from': admin})
            if gas > 16_000_000:
                raise SystemExit('Transaction exceeds gas cap')
            tx = fn.build_transaction({'from': admin, 'nonce': nonce, 'gas': min(gas + gas // 5, 16_000_000), 'gasPrice': w.eth.gas_price * 2})
            signed = account.sign_transaction(tx)
            entry = {'action': label, 'hash': signed.hash.to_0x_hex(), 'nonce': nonce, 'status': 'prepared'}
            record['transactions'].append(entry); save()
            w.eth.send_raw_transaction(signed.raw_transaction)
            receipt = w.eth.wait_for_transaction_receipt(signed.hash, timeout=180)
            entry['status'] = 'confirmed' if receipt['status'] == 1 else 'reverted'; save()
            if receipt['status'] != 1:
                raise SystemExit('Transaction reverted; inspect journal')
    record.update(after=snapshot(), admitted=registry.functions.isAdmitted(digest).call(),
                  enabled=network.functions.categories(category).call()[-1])
    save()
    if record['after'] != before or network.functions.categories(category).call() != ios_policy or record['enabled'] or (a.execute and not record['admitted']):
        raise SystemExit('Postcondition failed; inspect journal')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
