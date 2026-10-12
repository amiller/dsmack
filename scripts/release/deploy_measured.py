#!/usr/bin/env python3
"""Add measured admission to an existing V2 test network (contracts/MEASUREMENT_MIGRATION.md steps 1-3)."""
import argparse,json,os,time
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_abi import encode

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--rpc',required=True)
p.add_argument('--network',type=Path,required=True,help='Existing network file (DemoV1, macAdapter, macCategory)')
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
progress=a.out.with_suffix('.progress.json')
if a.out.exists() or progress.exists():raise SystemExit('Deployment output/progress exists; inspect its transactions before attempting another deployment')
w3=Web3(Web3.HTTPProvider(a.rpc,request_kwargs={'timeout':120}))
if w3.eth.chain_id not in (31337,84532):raise SystemExit('Test networks only')
account=Account.from_key(os.environ['PRIVATE_KEY'])
net=json.loads(a.network.read_text())
art=lambda n:json.loads((ROOT/'contracts/out'/f'{n}.sol'/f'{n}.json').read_text())
demo=w3.eth.contract(address=net['DemoV1'],abi=art('DemoV2')['abi'])
if demo.functions.owner().call()!=account.address:raise SystemExit('Signer is not the DemoV2 owner')
old=w3.eth.contract(address=net['macAdapter'],abi=art('AppleAttestRegistryV1')['abi'])
journal=[]
def save_progress():
    progress.parent.mkdir(parents=True,exist_ok=True)
    pending=progress.with_suffix('.tmp')
    pending.write_text(json.dumps({'chainId':w3.eth.chain_id,'admin':account.address,'transactions':journal},indent=2)+'\n')
    pending.replace(progress)
def send(label,fn):
    gas=fn.estimate_gas({'from':account.address})
    tx=fn.build_transaction({'from':account.address,'nonce':w3.eth.get_transaction_count(account.address,'pending'),'gas':min(gas+gas//5,16000000) if w3.eth.chain_id==84532 else gas*2,'gasPrice':w3.eth.gas_price*2})
    signed=account.sign_transaction(tx)
    entry={'label':label,'hash':signed.hash.to_0x_hex(),'nonce':tx['nonce'],'status':'prepared'}
    journal.append(entry);save_progress()
    w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt=w3.eth.wait_for_transaction_receipt(signed.hash,timeout=180)
    entry.update(status='confirmed' if receipt['status']==1 else 'reverted',block=receipt['blockNumber'],gasUsed=receipt['gasUsed'],contractAddress=receipt['contractAddress'])
    save_progress()
    if receipt['status']!=1:raise RuntimeError(f'{label} reverted')
    if w3.eth.chain_id==84532:time.sleep(4)
    return receipt
def contract(name,*args):
    artifact=art(name)
    factory=w3.eth.contract(abi=artifact['abi'],bytecode=artifact['bytecode']['object'])
    return w3.eth.contract(address=send(name,factory.constructor(*args))['contractAddress'],abi=artifact['abi'])
registry=contract('MeasurementRegistry')
adapter=contract('AppleAttestMeasuredV1',demo.address,registry.address,old.functions.aaguid().call(),old.functions.validationCategory().call(),False)
family=demo.functions.categories(Web3.to_bytes(hexstr=net['macCategory'])).call()[2]
policy=Web3.keccak(encode(['address'],[registry.address]))
id=demo.functions.addCategory(family,policy,adapter.address,True).call({'from':account.address})
send('addCategory',demo.functions.addCategory(family,policy,adapter.address,True))
send('setCategoryEnabled',demo.functions.setCategoryEnabled(id,True))
result={'chainId':w3.eth.chain_id,'admin':account.address,'DemoV1':demo.address,'measurementRegistry':registry.address,'measuredAdapter':adapter.address,'measuredCategory':Web3.to_hex(id),
 'family':Web3.to_hex(family),'policy':Web3.to_hex(policy),'adapterCodeHash':Web3.to_hex(w3.keccak(w3.eth.get_code(adapter.address))),
 'RegistryArtifact':'out/MeasurementRegistry.sol/MeasurementRegistry.json','AdapterArtifact':'out/AppleAttestMeasuredV1.sol/AppleAttestMeasuredV1.json',
 'transactions':[{k:e[k] for k in ('label','hash','block')} for e in journal]}
a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n')
progress.unlink()
print(json.dumps(result,indent=2))
