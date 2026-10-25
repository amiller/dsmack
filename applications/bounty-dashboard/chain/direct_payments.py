"""Read-only validation of explicitly selected direct ETH reward transactions."""
import json,pathlib,re
ABI=json.loads(pathlib.Path(__file__).with_name('abi.json').read_text())
ADDRESS=re.compile(r'0x[0-9a-f]{40}')
HASH=re.compile(r'0x[0-9a-f]{64}')
def need(value):
 if not value:raise ValueError('selected direct payment not verified')
def verify_source_withdrawal(record,c,rpc,direct):
 h=record['source_withdrawal_transaction_hash'];need(HASH.fullmatch(h)and h!=direct['hash'])
 tx=rpc('eth_getTransactionByHash',[h]);receipt=rpc('eth_getTransactionReceipt',[h])
 need(tx and receipt and receipt['status']=='0x1'and tx['hash']==receipt['transactionHash']==h)
 need(int(tx['chainId'],16)==84532 and tx['from'].lower()==receipt['from'].lower()==record['expected_from'])
 need(tx['to'].lower()==receipt['to'].lower()==c['address']and tx['input']=='0x'+ABI['selectors']['withdraw()']and int(tx['value'],16)==0)
 need(tx['blockHash']==receipt['blockHash']and tx['blockNumber']==receipt['blockNumber'])
 block=rpc('eth_getBlockByNumber',[receipt['blockNumber'],False]);need(block and block['hash']==receipt['blockHash']and h in block['transactions'])
 need((int(tx['blockNumber'],16),int(tx['transactionIndex'],16))<(int(direct['blockNumber'],16),int(direct['transactionIndex'],16)))
 event=next(e for e in ABI['events']if e['name']=='Withdrawn');topic='0x'+record['expected_from'][2:].rjust(64,'0')
 logs=[l for l in receipt['logs']if l.get('address','').lower()==c['address']and l.get('topics')==[event['topic'],topic]and not l.get('removed',False)]
 need(len(logs)==1 and logs[0]['data']=='0x'+format(int(record['amount_wei']),'064x'))
 need(rpc('eth_getBlockByNumber',[receipt['blockNumber'],False])['hash']==block['hash'])
 return h

def collect_direct(records,contracts,rpc_factory,observed_at):
 payments=[];seen=set();errors=0
 for record in records:
  try:
   need(record['chain_id']==84532 and HASH.fullmatch(record['transaction_hash']) and ADDRESS.fullmatch(record['expected_from']) and ADDRESS.fullmatch(record['recipient']))
   need(isinstance(record['amount_wei'],str)and re.fullmatch('[1-9][0-9]*',record['amount_wei']))
   key=(record['chain_id'],record['transaction_hash']);need(key not in seen);seen.add(key)
   c=next(c for c in contracts if c['chain_id']==record['chain_id']and record['task_key'].startswith(str(c['chain_id'])+':'+c['address']+':'))
   need(re.fullmatch(re.escape(str(c['chain_id'])+':'+c['address']+':')+'[1-9][0-9]*',record['task_key']))
   if record.get('attempt_id')is not None:need(re.fullmatch('[a-f0-9]{32}',record['attempt_id']))
   rpc=rpc_factory(c['rpc']);need(int(rpc('eth_chainId',[]),16)==84532)
   tx=rpc('eth_getTransactionByHash',[record['transaction_hash']]);receipt=rpc('eth_getTransactionReceipt',[record['transaction_hash']])
   need(tx and receipt and receipt['status']=='0x1'and tx['hash']==receipt['transactionHash']==record['transaction_hash'])
   need(int(tx['chainId'],16)==84532 and tx['from'].lower()==receipt['from'].lower()==record['expected_from'] and tx['to'].lower()==receipt['to'].lower()==record['recipient'])
   need(tx['input']=='0x'and int(tx['value'],16)==int(record['amount_wei'])and tx['blockHash']==receipt['blockHash']and tx['blockNumber']==receipt['blockNumber'])
   block=rpc('eth_getBlockByNumber',[receipt['blockNumber'],False]);need(block and block['hash']==receipt['blockHash']and tx['hash']in block['transactions'])
   need(rpc('eth_getBlockByNumber',[receipt['blockNumber'],False])['hash']==block['hash'])
   source=verify_source_withdrawal(record,c,rpc,tx) if record.get('source_withdrawal_transaction_hash') else None
   payments.append({'id':'direct:'+str(record['chain_id'])+':'+tx['hash'],'kind':'direct_reward','contract_id':str(c['chain_id'])+':'+c['address'],'task_key':record['task_key'],'attempt_id':record.get('attempt_id'),'chain_id':84532,'sender':record['expected_from'],'recipient':record['recipient'],'amount_wei':record['amount_wei'],'transaction_hash':tx['hash'],'block_number':int(receipt['blockNumber'],16),'block_hash':block['hash'],'timestamp':int(block['timestamp'],16),'observed_at':observed_at,'explorer_url':'https://sepolia.basescan.org/tx/'+tx['hash'],'receipt_verified':True,'economic_kind':'reward','reward_eligible':not bool(source),'source_withdrawal_transaction_hash':source,'attribution':'Operator-selected forwarding link to verified withdrawal; not cryptographic coin identity' if source else 'Operator-selected standalone direct reward; related task only, not WorkEscrow settlement'})
  except (ValueError,KeyError,TypeError,StopIteration,OSError):errors+=1
 source={'id':'direct-rewards','kind':'direct-payments','status':'partial'if errors else'ok','observed_at':observed_at,'count':len(payments),'scope':'Explicit operator-selected direct reward transactions only','error_code':'direct_payment_unverified'if errors else None,'counts':{'selected':len(records),'verified':len(payments),'unverified':errors}}
 return payments,source
