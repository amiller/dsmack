"""Read-only validation of explicitly selected direct ETH reward transactions."""
import re
ADDRESS=re.compile(r'0x[0-9a-f]{40}')
HASH=re.compile(r'0x[0-9a-f]{64}')
def need(value):
 if not value:raise ValueError('selected direct payment not verified')
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
   payments.append({'id':'direct:'+str(record['chain_id'])+':'+tx['hash'],'kind':'direct_reward','contract_id':str(c['chain_id'])+':'+c['address'],'task_key':record['task_key'],'attempt_id':record.get('attempt_id'),'chain_id':84532,'sender':record['expected_from'],'recipient':record['recipient'],'amount_wei':record['amount_wei'],'transaction_hash':tx['hash'],'block_number':int(receipt['blockNumber'],16),'block_hash':block['hash'],'timestamp':int(block['timestamp'],16),'observed_at':observed_at,'explorer_url':'https://sepolia.basescan.org/tx/'+tx['hash'],'receipt_verified':True,'attribution':'Operator-selected direct reward; related task only, not WorkEscrow settlement'})
  except (ValueError,KeyError,TypeError,StopIteration,OSError):errors+=1
 source={'id':'direct-rewards','kind':'direct-payments','status':'partial'if errors else'ok','observed_at':observed_at,'count':len(payments),'scope':'Explicit operator-selected direct reward transactions only','error_code':'direct_payment_unverified'if errors else None,'counts':{'selected':len(records),'verified':len(payments),'unverified':errors}}
 return payments,source
