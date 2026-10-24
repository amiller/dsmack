import copy,importlib.util,json,pathlib,unittest
s=importlib.util.spec_from_file_location('collect',pathlib.Path(__file__).with_name('collect.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
C=json.loads((m.HERE/'registry.json').read_text())['contracts'][0]
def word(n):return format(n,'064x')
class Mock:
 def __init__(self):self.ranges=[];self.chain=84532;self.badreceipt=False;self.logs=[]
 def __call__(self,method,p):
  if method=='eth_chainId':return hex(self.chain)
  if method=='eth_getBlockByNumber':return {'number':p[0],'hash':'0x'+'a'*64,'timestamp':'0x1'}
  if method=='eth_getLogs':self.ranges.append(p[0]);return self.logs
  if method=='eth_getTransactionReceipt':return {'status':'0x0' if self.badreceipt else '0x1','blockHash':'0x'+'a'*64,'transactionHash':'0x'+'b'*64,'to':C['address'],'logs':self.logs}
  raise ValueError('RPC failure')
class Tests(unittest.TestCase):
 def test_pagination_resume(self):
  r=Mock();h=C['deployment_block']+450;state,pages=m.scan(r,C,h,None,2);self.assertEqual(pages,2);self.assertEqual(state['through_block'],C['deployment_block']+399);self.assertEqual(int(r.ranges[0]['toBlock'],16)-int(r.ranges[0]['fromBlock'],16),199)
  state2,p=m.scan(r,C,h,state,2);self.assertEqual(state2['through_block'],h);self.assertEqual(p,1)
 def test_reorg_resets(self):
  r=Mock();old={'contract_id':'84532:'+C['address'],'through_block':C['deployment_block']+10,'through_hash':'wrong','events':[]};state,_=m.scan(r,C,C['deployment_block'],old,1);self.assertTrue(state['reorg_reset']);self.assertEqual(r.ranges[0]['fromBlock'],hex(C['deployment_block']))
 def test_wrong_chain_runtime_bad_rpc(self):
  r=Mock();r.chain=1;result,_=m.collect_contract(C,r,None,0);self.assertEqual(result['tasks'],[]);self.assertIn('wrong RPC chain',result['contracts'][0]['error'])
  r.chain=84532
  def rpc(method,p):
   if method=='eth_getBlockByNumber':return {'number':'0x1','hash':'0x'+'a'*64}
   if method=='eth_getCode':return '0x00'
   return r(method,p)
  result,_=m.collect_contract(C,rpc,None,0);self.assertIn('runtime mismatch',result['contracts'][0]['error'])
  result,_=m.collect_contract(C,lambda *args:(_ for _ in ()).throw(ValueError('provider error')),None,0);self.assertEqual(result['contracts'][0]['status'],'unknown')
 def test_receipt_provenance(self):
  r=Mock();e=next(x for x in m.ABI['events'] if x['name']=='Withdrawn');r.logs=[{'address':C['address'],'topics':[e['topic'],'0x'+word(1)],'data':'0x'+word(25),'blockNumber':hex(C['deployment_block']),'blockHash':'0x'+'a'*64,'transactionHash':'0x'+'b'*64,'logIndex':'0x0'}]
  state,_=m.scan(r,C,C['deployment_block'],None,1);self.assertEqual(state['events'][0]['fields']['amount'],'25');r.badreceipt=True
  with self.assertRaisesRegex(ValueError,'receipt mismatch'):m.scan(r,C,C['deployment_block'],None,1)
 def test_snapshot_amounts_and_pooled_payment(self):
  c=copy.deepcopy(C);c['runtime_sha256']=m.hashlib.sha256(b'\x01').hexdigest();r=Mock();head=c['deployment_block'];e=next(x for x in m.ABI['events'] if x['name']=='Withdrawn');r.logs=[{'address':c['address'],'topics':[e['topic'],'0x'+word(1)],'data':'0x'+word(25),'blockNumber':hex(head),'blockHash':'0x'+'a'*64,'transactionHash':'0x'+'b'*64,'logIndex':'0x0'}]
  def rpc(method,p):
   if method=='eth_getBlockByNumber':return {'number':hex(head),'hash':'0x'+'a'*64,'timestamp':'0x1'}
   if method=='eth_getCode':return '0x01'
   if method=='eth_call':
    selector=p[0]['data'][2:10]
    for name in ['nextTask','nextAssignment']:
     if selector==m.ABI['selectors'][name+'()']:return '0x'+word(2)
    fields=m.flatfields(m.ABI['functions']['task' if selector==m.ABI['selectors']['task(uint256)'] else 'assignment']);return '0x'+''.join(word(1 if f['type'] in ['bool','address'] or f['name'] in ['taskId','state'] else 100000000000000 if f['name'] in ['available','completionPay','reserved'] else 0) for f in fields)
   return r(method,p)
  result,state=m.collect_contract(c,rpc,None,1);self.assertEqual(result['contracts'][0]['status'],'observed');self.assertTrue(result['contracts'][0]['coverage']['events_complete']);self.assertEqual(result['tasks'][0]['available_wei'],'100000000000000');self.assertIsNone(result['tasks'][0]['deposited_wei']);self.assertEqual(result['payments'][0]['amount_wei'],'25');self.assertIsNone(result['payments'][0]['task_key']);self.assertEqual(result['payments'][0]['kind'],'withdrawal')
 def test_abi_refuses_malformed(self):
  with self.assertRaises(ValueError):m.decode([{'name':'v','type':'uint8'}],'0x'+word(256))
  with self.assertRaises(ValueError):m.decode([{'name':'v','type':'address'}],'0x'+word(2**160))
if __name__=='__main__':unittest.main()
