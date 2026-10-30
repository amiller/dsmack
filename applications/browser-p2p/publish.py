#!/usr/bin/env python3
"""Deploy/update the Base Sepolia tunnel index, then publish the same hints to the broker."""
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
from deploy import load_owner,send
from rpc import Quorum,CHAIN_ID,call
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('action',choices=['deploy','publish','broker'])
p.add_argument('--key',type=Path)
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--bytecode',type=Path)
p.add_argument('--registry')
p.add_argument('--entries',type=Path)
p.add_argument('--broker')
p.add_argument('--operator-token',type=Path)
p.add_argument('--publisher-address',help='Mac-local publisher address, checked before signing')
p.add_argument('--rpc',help='explicit single RPC for Mac-local zero-value locator publications')
p.add_argument('--registry-owner',help='Initial publisher when deploying a registry')
a=p.parse_args();a.evidence.mkdir(parents=True,exist_ok=True)
def publish_broker():
 if not a.entries or not a.broker:raise ValueError('entries and broker required')
 raw=json.dumps(json.loads(a.entries.read_text()),separators=(',',':'))
 headers={'Content-Type':'application/json'}
 if a.operator_token:headers['Authorization']='Bearer '+a.operator_token.read_text().strip()
 else:
  signer=publisher()
  body={'entries':json.loads(raw),'publisher':signer.address.lower(),'expiresAt':int(__import__('time').time())+3300}
  canonical=json.dumps(body,sort_keys=True,separators=(',',':'))
  body['signature']='0x'+signer.sign_message(encode_defunct(text='dsmack-tunnels/1\n'+canonical)).signature.hex()
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
if a.rpc and (a.action!='publish' or not a.publisher_address or not a.rpc.startswith('https://')):
 raise ValueError('--rpc requires a Mac-local locator publication and an HTTPS RPC')
class PublicationRPC(Quorum):
 def __init__(self):
  if a.rpc:
   self.urls=(a.rpc,)
   (a.evidence/'publication-rpc.json').write_text(json.dumps({'url':a.rpc,'chainId':CHAIN_ID}))
  else:super().__init__()
 def finalized(self):
  if not a.rpc:return super().finalized()
  if self.read('eth_chainId',[])!=hex(CHAIN_ID):raise ValueError('publisher RPC is not Base Sepolia')
  header=self.read('eth_getBlockByNumber',['finalized',False])
  return {k:header[k] for k in ('number','hash','timestamp')}
 def read(self,method,params):
  if a.rpc:return call(a.rpc,method,params)
  if method!='eth_gasPrice':return super().read(method,params)
  # Fee suggestions are volatile estimates, not consensus state. Use the largest
  # successful public quote; send() still enforces its fee/reserve caps.
  quotes={};values=[]
  for url in self.urls:
   try:
    value=call(url,method,params);values.append(int(value,16));quotes[url]=value
   except Exception as error:quotes[url]={'error':str(error)}
  (a.evidence/'fee-quotes.json').write_text(json.dumps(quotes,indent=2)+'\n')
  if not values:raise RuntimeError('all fee quote requests failed; see fee-quotes.json')
  print('Fee suggestions recorded; using maximum '+str(max(values))+' wei',flush=True)
  return hex(max(values))
quorum=PublicationRPC()
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
 if not a.registry or not a.entries or not a.broker:raise ValueError('registry, entries and broker required')
 if (a.evidence/'publish-transaction.json').exists():raise ValueError('publication already submitted; inspect its receipt')
 values=json.loads(a.entries.read_text());raw=json.dumps(values,separators=(',',':'))
 data='0x'+(keccak(text='publish(string)')[:4]+encode(['string'],[raw])).hex()
 receipt=send(account,quorum,a.evidence,'publish',to=a.registry,data=data,**({'min_reserve_wei':100_000_000_000_000,'balance_block':'latest'} if a.publisher_address else {}))
 publish_broker()
 print(json.dumps({'chainId':CHAIN_ID,'registry':a.registry,'transactionHash':receipt['transactionHash'],'broker':a.broker}))
