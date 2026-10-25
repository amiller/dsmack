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
 def test_duplicate_selected_tx_counted_once(self):
  rows,s=self.collect([self.record,self.record]);self.assertEqual(len(rows),1);self.assertEqual(s['counts']['unverified'],1)
if __name__=='__main__':unittest.main()
