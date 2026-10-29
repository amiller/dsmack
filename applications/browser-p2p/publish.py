#!/usr/bin/env python3
"""Deploy/update the Base Sepolia tunnel index, then publish the same hints to the broker."""
import argparse,json,os,sys
from pathlib import Path
from urllib.request import Request,urlopen
from eth_abi import encode
from eth_utils import keccak
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'contracts/payments'))
from deploy import load_owner,send
from rpc import Quorum,CHAIN_ID,call
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('action',choices=['deploy','publish'])
p.add_argument('--key',type=Path,required=True)
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--bytecode',type=Path)
p.add_argument('--registry')
p.add_argument('--entries',type=Path)
p.add_argument('--broker')
p.add_argument('--operator-token',type=Path)
a=p.parse_args();account=load_owner(a.key);a.evidence.mkdir(parents=True,exist_ok=True)
class PublicationRPC(Quorum):
 def read(self,method,params):
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
 receipt=send(account,quorum,a.evidence,'deploy',data='0x'+raw)
 record={'chainId':CHAIN_ID,'registry':receipt['contractAddress'],'transactionHash':receipt['transactionHash'],'entriesSelector':'0x'+keccak(text='entries()')[:4].hex()}
 (a.evidence/'registry.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
else:
 if not a.registry or not a.entries or not a.broker or not a.operator_token:raise ValueError('registry, entries, broker and operator-token required')
 if (a.evidence/'publish-transaction.json').exists():raise ValueError('publication already submitted; inspect its receipt')
 values=json.loads(a.entries.read_text());raw=json.dumps(values,separators=(',',':'))
 data='0x'+(keccak(text='publish(string)')[:4]+encode(['string'],[raw])).hex()
 receipt=send(account,quorum,a.evidence,'publish',to=a.registry,data=data)
 request=Request(a.broker,raw.encode(),{'Content-Type':'application/json','Authorization':'Bearer '+a.operator_token.read_text().strip()},method='POST')
 with urlopen(request,timeout=30) as response:result=json.load(response)
 (a.evidence/'broker-published.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'chainId':CHAIN_ID,'registry':a.registry,'transactionHash':receipt['transactionHash'],'broker':a.broker}))
