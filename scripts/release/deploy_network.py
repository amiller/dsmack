#!/usr/bin/env python3
"""Deploy a separate V2 test network; never modify an existing deployment."""
import argparse,json,os,time
from pathlib import Path
from web3 import Web3
from eth_account import Account

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--rpc',required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--publisher-team',help='Deploy NFT badges and account factory for this publisher Team ID')
p.add_argument('--activate',action='store_true',help='Enable admission immediately (otherwise deploy paused)')
p.add_argument('--category',type=int,choices=(3,6),default=6)
a=p.parse_args()
if a.publisher_team and (len(a.publisher_team)!=10 or not a.publisher_team.isascii() or not a.publisher_team.isalnum() or a.publisher_team.upper()!=a.publisher_team):raise SystemExit('Invalid publisher Team ID')
progress=a.out.with_suffix('.progress.json')
if a.out.exists() or progress.exists():raise SystemExit('Deployment output/progress exists; inspect its transactions before attempting another deployment')
w3=Web3(Web3.HTTPProvider(a.rpc,request_kwargs={'timeout':120}))
if w3.eth.chain_id not in (31337,84532):raise SystemExit('Test networks only')
account=Account.from_key(os.environ['PRIVATE_KEY'])
receipts=[]
journal=[]
def save_progress():
    progress.parent.mkdir(parents=True,exist_ok=True)
    pending=progress.with_suffix('.tmp')
    pending.write_text(json.dumps({'chainId':w3.eth.chain_id,'admin':account.address,'transactions':journal},indent=2)+'\n')
    pending.replace(progress)
def send(fn):
    gas=fn.estimate_gas({'from':account.address})
    tx=fn.build_transaction({'from':account.address,'nonce':w3.eth.get_transaction_count(account.address,'pending'),'gas':min(gas+gas//5,16000000) if w3.eth.chain_id==84532 else gas*2,'gasPrice':w3.eth.gas_price*2})
    signed=account.sign_transaction(tx)
    destination=tx.get('to')
    if isinstance(destination,bytes):destination=Web3.to_hex(destination) if destination else None
    entry={'hash':signed.hash.to_0x_hex(),'nonce':tx['nonce'],'to':destination,'status':'prepared'}
    journal.append(entry);save_progress()
    w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt=w3.eth.wait_for_transaction_receipt(signed.hash,timeout=180)
    entry.update(status='confirmed' if receipt['status']==1 else 'reverted',contractAddress=receipt['contractAddress'])
    save_progress()
    if receipt['status']!=1:raise RuntimeError('Deployment transaction reverted')
    receipts.append(receipt['transactionHash'].to_0x_hex())
    if w3.eth.chain_id==84532:time.sleep(4)
    return receipt

def contract(name,*args,source=None):
    artifact=json.loads((ROOT/'contracts/out'/f'{source or name}.sol'/f'{name}.json').read_text())
    factory=w3.eth.contract(abi=artifact['abi'],bytecode=artifact['bytecode']['object'])
    address=send(factory.constructor(*args))['contractAddress']
    return w3.eth.contract(address=address,abi=artifact['abi'])
cds=contract('CDRegistry')
build=json.loads(a.build.read_text())
b=lambda k:bytes.fromhex(build[k].removeprefix('0x'))
send(cds.functions.setBuild(b('cd'),b('page0'),b('ent'),build['linkeditCmd'],build['codeSigCmd']))
send(cds.functions.registerBuild(b('cd'),b('page0'),b('ent')))
demo=contract('DemoV2',account.address)
adapter=contract('AppleAttestRegistryV1',demo.address,cds.address,bytes.fromhex('61707061747465737400000000000000'),a.category,False)
family=b'apple-macos'.ljust(32,b'\0')
from eth_abi import encode
policy=Web3.keccak(encode(['address'],[cds.address]))
id=demo.functions.addCategory(family,policy,adapter.address,True).call({'from':account.address})
send(demo.functions.addCategory(family,policy,adapter.address,True))
send(demo.functions.setCategoryEnabled(id,True))
if a.activate:send(demo.functions.setPaused(False))
result={'protocolVersion':2,'chainId':w3.eth.chain_id,'admin':account.address,'DemoV1':demo.address,'macCDRegistry':cds.address,'macAdapter':adapter.address,'macCategory':Web3.to_hex(id),'DemoV1Artifact':'out/DemoV2.sol/DemoV2.json','CDRegistryArtifact':'out/CDRegistry.sol/CDRegistry.json','AdapterArtifact':'out/AppleAttestRegistryV1.sol/AppleAttestRegistryV1.json','transactions':receipts}
if a.publisher_team:
    import hashlib
    badges=contract('ResearchBadges',demo.address,adapter.address,id,hashlib.sha256(a.publisher_team.encode()).digest())
    factory=contract('PersonalBadgeAccountFactory',badges.address,source='PersonalBadgeAccount')
    result.update(ResearchBadges=badges.address,PersonalBadgeAccountFactory=factory.address,publisherTeam=a.publisher_team)
a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
