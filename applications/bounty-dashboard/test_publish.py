import unittest,importlib.util,pathlib,tempfile,os,json
from unittest.mock import patch
s=importlib.util.spec_from_file_location('publisher',pathlib.Path(__file__).with_name('publish.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class Tests(unittest.TestCase):
 def chain(self):return {'built_at':'2026-10-24T12:00:00Z','contracts':[{'id':'84532:c','chain_id':84532,'network':'Base Sepolia','testnet':True,'status':'observed','observed_at':'2026-10-24T12:00:00Z','coverage':{'events_complete':False},'rpc':'https://private/RPC_SECRET'}],'tasks':[],'assignments':[],'payments':[],'activity':[],'credits':[],'sources':[{'rpc':'RPC_SECRET'}]}
 def test_projection_scope_and_incomplete_history(self):
  x=p.normalize(self.chain(),[]);self.assertNotIn('RPC_SECRET',json.dumps(x));self.assertEqual(x['chain']['sources'][0]['status'],'indexing');self.assertEqual(x['observed_at'],'2026-10-24T12:00:00Z')
 def test_activity_join_and_order_without_assigning_pooled_withdrawal(self):
  c=self.chain();c['assignments']=[{'key':'84532:c:assignment:1','contract_id':'84532:c','task_key':'84532:c:10'}]
  c['activity']=[{'contract_id':'84532:c','event':'Submitted','fields':{'assignmentId':'1'},'transaction_hash':'0x1','log_index':0,'timestamp':1},{'contract_id':'84532:c','event':'Withdrawn','fields':{'account':'0xabc'},'transaction_hash':'0x2','log_index':0,'timestamp':2}]
  x=p.normalize(c,[])['chain']['activity'];self.assertEqual(x[0]['kind'],'Withdrawal');self.assertIsNone(x[0]['task_key']);self.assertEqual(x[1]['task_key'],'84532:c:10')
 def test_token_permission_guard_precedes_network(self):
  with tempfile.TemporaryDirectory()as d:
   f=pathlib.Path(d)/'token';f.write_text('A'*43);f.chmod(0o644)
   with patch.object(p.urllib.request,'build_opener')as net:
    with self.assertRaises(ValueError):p.send(p.normalize(self.chain(),[]),f)
    net.assert_not_called()
 def test_fixed_authenticated_dashboard_put_no_chain_or_wallet_calls(self):
  with tempfile.TemporaryDirectory()as d:
   f=pathlib.Path(d)/'token';f.write_text('A'*43);f.chmod(0o600)
   class R:
    status=200
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def read(self,*a):return b'{"accepted":true}'
   class Net:
    def open(self,req,timeout):
     self_req=req;assert req.full_url==p.ENDPOINT and req.method=='PUT';assert req.headers['Authorization']=='Bearer '+'A'*43;assert b'RPC_SECRET'not in req.data;return R()
   with patch.object(p.urllib.request,'build_opener',return_value=Net()):self.assertTrue(p.send(p.normalize(self.chain(),[]),f)['accepted'])
if __name__=='__main__':unittest.main()
