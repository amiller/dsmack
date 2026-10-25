import copy,json,pathlib,unittest
from direct_payments import collect_direct
class Tests(unittest.TestCase):
 def setUp(self):
  self.record=json.loads(pathlib.Path(__file__).with_name('direct-payments.json').read_text())['payments'][0];r=self.record;self.h='0x'+'a'*64
  self.contract={'chain_id':84532,'address':r['task_key'].split(':')[1],'rpc':'https://rpc.invalid/SECRET'}
  self.tx={'hash':r['transaction_hash'],'chainId':hex(84532),'from':r['expected_from'],'to':r['recipient'],'value':hex(int(r['amount_wei'])),'input':'0x','blockHash':self.h,'blockNumber':'0x123'}
  self.receipt={'transactionHash':r['transaction_hash'],'from':r['expected_from'],'to':r['recipient'],'status':'0x1','blockHash':self.h,'blockNumber':'0x123'}
  self.block={'hash':self.h,'timestamp':'0x234','transactions':[r['transaction_hash']]}
 def rpc(self,method,params):
  return {'eth_chainId':hex(84532),'eth_getTransactionByHash':self.tx,'eth_getTransactionReceipt':self.receipt,'eth_getBlockByNumber':self.block}[method]
 def collect(self,records=None):return collect_direct(records or[self.record],[self.contract],lambda _:self.rpc,'2026-10-25T00:00:00Z')
 def test_verified_direct_transfer_is_not_escrow_and_no_rpc_secret(self):
  rows,s=self.collect();self.assertEqual(len(rows),1);self.assertEqual(rows[0]['kind'],'direct_reward');self.assertTrue(rows[0]['receipt_verified']);self.assertIn('not WorkEscrow',rows[0]['attribution']);self.assertNotIn('SECRET',json.dumps([rows,s]));self.assertEqual(s['status'],'ok')
 def test_failed_receipt_wrong_chain_sender_recipient_value_or_call_refuse(self):
  for obj,key,value in[(self.receipt,'status','0x0'),(self.tx,'chainId','0x1'),(self.tx,'from','0x'+'0'*40),(self.tx,'to','0x'+'0'*40),(self.tx,'value','0x1'),(self.tx,'input','0x1234')]:
   old=obj[key];obj[key]=value;rows,s=self.collect();self.assertEqual(rows,[]);self.assertEqual(s['status'],'partial');obj[key]=old
 def test_noncanonical_or_missing_tx_refuses(self):
  self.block['hash']='0x'+'b'*64;self.assertEqual(self.collect()[0],[]);self.block['hash']=self.h;self.block['transactions']=[];self.assertEqual(self.collect()[0],[])
 def test_verified_forward_link_excludes_second_reward_and_refuses_bad_source(self):
  r=self.record;source='0x'+'c'*64;r['source_withdrawal_transaction_hash']=source
  self.tx['transactionIndex']='0x1'
  stx={**self.tx,'hash':source,'to':self.contract['address'],'value':'0x0','input':'0x3ccfd60b','transactionIndex':'0x0'}
  from direct_payments import ABI
  event=next(e for e in ABI['events']if e['name']=='Withdrawn')
  receipt={**self.receipt,'transactionHash':source,'to':self.contract['address'],'logs':[{'address':self.contract['address'],'topics':[event['topic'],'0x'+r['expected_from'][2:].rjust(64,'0')],'data':'0x'+format(int(r['amount_wei']),'064x')}]}
  self.block['transactions'].append(source)
  def rpc(method,params):
   if method=='eth_getTransactionByHash'and params==[source]:return stx
   if method=='eth_getTransactionReceipt'and params==[source]:return receipt
   return self.rpc(method,params)
  def collect():return collect_direct([r],[self.contract],lambda _:rpc,'now')
  rows,_=collect();self.assertEqual(rows[0]['source_withdrawal_transaction_hash'],source);self.assertIs(rows[0]['reward_eligible'],False)
  for obj,key,value in[(receipt,'status','0x0'),(stx,'input','0x1234'),(stx,'from','0x'+'0'*40),(stx,'value','0x1')]:
   old=obj[key];obj[key]=value;self.assertEqual(collect()[0],[]);obj[key]=old
  receipt['logs'][0]['data']='0x'+format(1,'064x');self.assertEqual(collect()[0],[])
 def test_duplicate_selected_tx_counted_once(self):
  rows,s=self.collect([self.record,self.record]);self.assertEqual(len(rows),1);self.assertEqual(s['counts']['unverified'],1)
if __name__=='__main__':unittest.main()
