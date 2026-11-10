#!/usr/bin/env python3
"""Publish Mac-signed tunnel hints to Base Sepolia or the broker."""
import argparse,json,os,sys,time
from http.client import HTTPException
from urllib.error import HTTPError,URLError
from pathlib import Path
from urllib.request import Request,urlopen
from eth_abi import encode
from eth_utils import keccak
from eth_account import Account
from eth_account.messages import encode_defunct
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'contracts/payments'))
from deploy import load_owner,send,wait_receipt
from rpc import ChainReader,CHAIN_ID
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('action',choices=['deploy','publish','chain','broker'])
p.add_argument('--key',type=Path)
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--bytecode',type=Path)
p.add_argument('--registry')
p.add_argument('--entries',type=Path)
p.add_argument('--broker')
p.add_argument('--operator-token',type=Path)
p.add_argument('--publisher-address',help='Mac-local publisher address, checked before signing')
p.add_argument('--rpc',action='append',help='ordered RPC for Mac-local zero-value locator publications; repeat for several hosts')
p.add_argument('--expiry-state',type=Path,help='shared publication expiry across launcher generations')
p.add_argument('--registry-owner',help='Initial publisher when deploying a registry')
a=p.parse_args();a.evidence.mkdir(parents=True,exist_ok=True)
def signed_publication(entries, signer):
 now=int(time.time())
 expiry=max((entry['expiresAt'] for entry in entries),default=now+3300)
 if not now<expiry<=now+3600:raise ValueError('tunnel publication expiry must be within one hour')
 if a.expiry_state and a.expiry_state.exists():expiry=max(expiry,int(a.expiry_state.read_text())+1)
 if expiry>now+3600:
  time.sleep(expiry-now-3600)
  now=int(time.time())
 if not now<expiry<=now+3600:raise ValueError('tunnel publication expiry must be within one hour')
 if a.expiry_state:
  temporary=a.expiry_state.with_suffix('.tmp');temporary.write_text(str(expiry));temporary.replace(a.expiry_state)
 body={'entries':entries,'publisher':signer.address.lower(),'expiresAt':expiry}
 canonical=json.dumps(body,sort_keys=True,separators=(',',':'))
 body['signature']='0x'+signer.sign_message(encode_defunct(text='dsmack-tunnels/1\n'+canonical)).signature.hex()
 return body

def publish_broker():
 if not a.entries or not a.broker:raise ValueError('entries and broker required')
 raw=json.dumps(json.loads(a.entries.read_text()),separators=(',',':'))
 headers={'Content-Type':'application/json'}
 if a.operator_token:headers['Authorization']='Bearer '+a.operator_token.read_text().strip()
 else:
  signer=publisher()
  body=signed_publication(json.loads(raw),signer)
  raw=json.dumps(body,separators=(',',':'))
 request=Request(a.broker,raw.encode(),headers,method='POST')
 for attempt in range(1,4):
  try:
   with urlopen(request,timeout=30) as response:result=json.load(response)
   break
  except (HTTPError,URLError,TimeoutError,HTTPException,OSError) as error:
   record={'stage':'broker_publication','attempt':attempt,'status':getattr(error,'code',None),'error':str(error),'body':'','body_truncated':False}
   transient=not isinstance(error,HTTPError) or error.code in (408,429) or 500<=error.code<600
   if isinstance(error,HTTPError):
    try:
     body=error.read(4097);record['body']=body[:4096].decode(errors='replace');record['body_truncated']=len(body)>4096
    except (OSError,HTTPException) as body_error:record['body_read_error']=str(body_error)
    finally:error.close()
   if a.expiry_state and record['status']==400:
    try:refusal=json.loads(record['body'])
    except ValueError:refusal={}
    if (isinstance(refusal,dict) and refusal.get('error')=='stale publisher update'
        and type(refusal.get('expiresAt')) is int and int(time.time())<refusal['expiresAt']<=int(time.time())+3600):
     expiry=max(int(a.expiry_state.read_text()) if a.expiry_state.exists() else 0,refusal['expiresAt'])
     temporary=a.expiry_state.with_suffix('.tmp');temporary.write_text(str(expiry));temporary.replace(a.expiry_state)
   record['retrying']=transient and attempt<3
   (a.evidence/('broker-error-'+str(attempt)+'.json')).write_text(json.dumps(record,indent=2)+'\n')
   print(json.dumps(record),flush=True)
   if not record['retrying']:raise RuntimeError('broker publication failed; last error: '+json.dumps(record)) from error
   time.sleep(5)
 (a.evidence/'broker-published.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'broker':a.broker,'published':True}))
def publisher():
 if not a.publisher_address:return load_owner(a.key)
 account=Account.from_key(a.key.read_text().strip())
 if account.address.lower()!=a.publisher_address.lower():raise ValueError('publisher key/address mismatch')
 return account
if a.action=='broker':publish_broker();sys.exit()
if not a.key:raise ValueError('--key required for Base Sepolia writes')
account=publisher()
if a.rpc and (a.action not in ('publish','chain') or not a.publisher_address or not all(url.startswith('https://') for url in a.rpc)):
 raise ValueError('--rpc requires a Mac-local locator publication and an HTTPS RPC')
quorum=ChainReader(tuple(a.rpc)) if a.rpc else ChainReader()
if CHAIN_ID!=84532:raise ValueError('Base Sepolia required')
if a.action=='deploy':
 if not a.bytecode:raise ValueError('--bytecode required')
 if (a.evidence/'deploy-transaction.json').exists():raise ValueError('deployment already submitted; inspect its receipt')
 raw=a.bytecode.read_text().strip().removeprefix('0x')
 raw+=encode(['address'],[a.registry_owner or account.address]).hex()
 receipt=send(account,quorum,a.evidence,'deploy',data='0x'+raw)
 record={'chainId':CHAIN_ID,'registry':receipt['contractAddress'],'transactionHash':receipt['transactionHash'],'entriesSelector':'0x'+keccak(text='entries()')[:4].hex()}
 (a.evidence/'registry.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
else:
 if not a.registry or not a.entries:raise ValueError('registry and entries required')
 if a.action=='publish' and not a.broker:raise ValueError('publish requires broker; use chain for chain-only publication')
 values=json.loads(a.entries.read_text())
 transaction=a.evidence/'publish-transaction.json'
 if transaction.exists():
  if a.action!='chain':raise ValueError('publication already submitted; inspect its receipt')
  prior=json.loads(transaction.read_text())
  envelope=json.loads((a.evidence/'signed-publication.json').read_text())
  if (envelope['entries']!=values or prior['to'].lower()!=a.registry.lower()
      or prior['from'].lower()!=account.address.lower()):
   raise ValueError('pending publication differs; reconcile its original entries and publisher first')
  receipt=wait_receipt(quorum,prior['hash'])
  (a.evidence/'publish-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 else:
  envelope=signed_publication(values,account);raw=json.dumps(envelope,separators=(',',':'))
  (a.evidence/'signed-publication.json').write_text(json.dumps(envelope,indent=2)+'\n')
  data='0x'+(keccak(text='publish(string)')[:4]+encode(['string'],[raw])).hex()
  receipt=send(account,quorum,a.evidence,'publish',to=a.registry,data=data,**({'min_reserve_wei':100_000_000_000_000,'balance_block':'latest'} if a.publisher_address else {}))
 if a.action=='publish':publish_broker()
 print(json.dumps({'chainId':CHAIN_ID,'registry':a.registry,'transactionHash':receipt['transactionHash'],'broker':a.broker}))
