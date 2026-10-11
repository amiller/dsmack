#!/usr/bin/env python3
"""Add an INACTIVE TestFlight category to an existing V2 test network.

No baseline is set and no category is enabled. This cannot make an iPhone join.
PRIVATE_KEY is read only from the environment. Coordinate the administrator's
nonce with any running sponsor before live use; the journal forbids blind reruns.
"""
import argparse,hashlib,json,os,time
from pathlib import Path
from eth_account import Account
from eth_abi import encode
from web3 import Web3

ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--rpc',required=True)
 p.add_argument('--existing',type=Path,required=True)
 p.add_argument('--out',type=Path,required=True)
 a=p.parse_args();previous=json.loads(a.existing.read_text())
 journal=a.out.with_suffix('.progress.json')
 if a.out.exists() or journal.exists():raise SystemExit('Output/journal exists; reconcile transactions before another deployment')
 w=Web3(Web3.HTTPProvider(a.rpc,request_kwargs={'timeout':120}))
 if w.eth.chain_id not in (31337,84532) or w.eth.chain_id!=previous['chainId']:raise SystemExit('Wrong test chain')
 account=Account.from_key(os.environ['PRIVATE_KEY'])
 def artifact(name,source=None):return json.loads((ROOT/'contracts/out'/f'{source or name}.sol'/f'{name}.json').read_text())
 def existing(name,address):return w.eth.contract(address=Web3.to_checksum_address(address),abi=artifact(name)['abi'])
 network=existing('DemoV2',previous['DemoV1']);mac=existing('CDRegistry',previous['macCDRegistry'])
 if account.address.lower()!=previous['admin'].lower() or network.functions.owner().call()!=account.address:raise SystemExit('Wrong administrator')
 publisher=previous['publisherTeam']
 if len(publisher)!=10 or not publisher.isascii() or not publisher.isalnum() or publisher!=publisher.upper():raise SystemExit('Invalid publisher team')
 publisher_hash=hashlib.sha256(publisher.encode()).digest()
 badges=existing('ResearchBadges',previous['ResearchBadges'])
 if badges.functions.publisherTeam().call()!=publisher_hash:raise SystemExit('Publisher differs from existing badge policy')
 category=bytes.fromhex(previous['macCategory'].removeprefix('0x'))
 before={'paused':network.functions.paused().call(),'macBuildId':Web3.to_hex(mac.functions.buildId().call()),'macCategory':list(network.functions.categories(category).call())}
 # Convert public bytes values before writing the preservation snapshot.
 before['macCategory']=[Web3.to_hex(v) if isinstance(v,bytes) else v for v in before['macCategory']]
 record={'chainId':w.eth.chain_id,'admin':account.address,'DemoV1':network.address,'before':before,'transactions':[]}
 def save():
  journal.parent.mkdir(parents=True,exist_ok=True);tmp=journal.with_suffix('.tmp');tmp.write_text(json.dumps(record,indent=2)+'\n');tmp.replace(journal)
 def send(fn,label):
  estimate=fn.estimate_gas({'from':account.address})
  if w.eth.chain_id==84532 and estimate>16000000:raise RuntimeError('Transaction exceeds Base gas cap')
  tx=fn.build_transaction({'from':account.address,'nonce':w.eth.get_transaction_count(account.address,'pending'),'gas':min(estimate+estimate//5,16000000) if w.eth.chain_id==84532 else estimate*2,'gasPrice':w.eth.gas_price*2})
  signed=account.sign_transaction(tx)
  entry={'action':label,'hash':signed.hash.to_0x_hex(),'nonce':tx['nonce'],'status':'prepared'}
  record['transactions'].append(entry);save()
  w.eth.send_raw_transaction(signed.raw_transaction)
  receipt=w.eth.wait_for_transaction_receipt(signed.hash,timeout=180)
  entry.update(status='confirmed' if receipt['status']==1 else 'reverted',contractAddress=receipt['contractAddress']);save()
  if receipt['status']!=1:raise RuntimeError('Transaction reverted')
  if w.eth.chain_id==84532:time.sleep(4)
  return receipt
 def deploy(name,*args,source=None):
  value=artifact(name,source);factory=w.eth.contract(abi=value['abi'],bytecode=value['bytecode']['object'])
  address=send(factory.constructor(*args),'deploy '+name)['contractAddress']
  return w.eth.contract(address=address,abi=value['abi'])
 cds=deploy('CDRegistry')
 adapter=deploy('AppleAttestRegistryV1',network.address,cds.address,bytes.fromhex('61707061747465737400000000000000'),2,True)
 family=b'apple-ios-testflight'.ljust(32,b'\0');policy=Web3.keccak(encode(['address'],[cds.address]))
 add=network.functions.addCategory(family,policy,adapter.address,True)
 ios_category=add.call({'from':account.address});send(add,'add disabled iPhone category')
 ios_badges=deploy('ResearchBadges',network.address,adapter.address,ios_category,publisher_hash)
 factory=deploy('PersonalBadgeAccountFactory',ios_badges.address,source='PersonalBadgeAccount')
 after={'paused':network.functions.paused().call(),'macBuildId':Web3.to_hex(mac.functions.buildId().call()),'macCategory':[Web3.to_hex(v) if isinstance(v,bytes) else v for v in network.functions.categories(category).call()]}
 if after!=before:raise RuntimeError('Existing Mac policy changed during preparation; inspect journal')
 if network.functions.categories(ios_category).call()[-1] or cds.functions.buildId().call()!=bytes(32):raise RuntimeError('iPhone category unexpectedly active or populated')
 result={'protocolVersion':2,'chainId':w.eth.chain_id,'admin':account.address,'DemoV1':network.address,'iosCDRegistry':cds.address,'iosAdapter':adapter.address,'iosCategory':Web3.to_hex(ios_category),'ResearchBadges':ios_badges.address,'PersonalBadgeAccountFactory':factory.address,'publisherTeam':publisher,'validationCategory':2,'enabled':False,'baselineConfigured':False,'existingMacPolicyUnchanged':True,'transactions':[t['hash'] for t in record['transactions']]}
 record['result']=result;save();a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
