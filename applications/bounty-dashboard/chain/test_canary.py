import copy,hashlib,importlib.util,json,pathlib,unittest
s=importlib.util.spec_from_file_location('canary',pathlib.Path(__file__).with_name('canary.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
C=next(c for c in json.loads((m.HERE/'registry.json').read_text())['canaries'] if c['codec']=='canary-read-codec/1')
H='0x'+'a'*64
def word(n):return format(n,'064x')
# Recorded from Base Sepolia: Armed log of tx 0x3e73a6...f2b8 and entries(0) at block 50203471.
ARMED={'address':C['address'],'topics':['0xa741985cbb340e4a54364c91c45401f5819fa7009a0a812f8461c6fdb2be64d0','0x'+word(0)],'data':'0x'+word(0)+'9e733cee03debdd1080c9de6f1a3cdd23fdacdfb74c15fd48c8fe02069d62bb8'+word(0)*2+'000000000000000000000000000000000000000000000000002386f26fc10000'+word(0x6b54fb59)}
ENTRY0='0x'+word(0)+'9e733cee03debdd1080c9de6f1a3cdd23fdacdfb74c15fd48c8fe02069d62bb8'+word(0)*2+'00000000000000000000000097883cb4b2f21530277f86490d8881654e36e6aa'+word(0x6b54fb59)+'000000000000000000000000000000000000000000000000002386f26fc10000'+word(0)
# Entry 1 burned by claimant 0x...c1 for 5 wei.
ARMED1={**ARMED,'topics':[ARMED['topics'][0],'0x'+word(1)]}
BURNED={'address':C['address'],'topics':['0x5a00dc4f82511de1770bf4dead5148d161be7af4dcf586cedb9d88643cf1ee11','0x'+word(1)],'data':'0x'+word(0)+word(0xc1)+word(5)}
ENTRY1=ENTRY0[:-64*2]+word(0)+word(1)
class Chain:
 def __init__(self,code,logs):
  self.code=code;self.logs=[{**l,'blockNumber':hex(C['deployment_block']),'blockHash':H,'transactionHash':'0x'+word(i+1),'logIndex':hex(i),'removed':False} for i,l in enumerate(logs)]
 def __call__(self,method,p):
  if method=='eth_chainId':return hex(84532)
  if method=='eth_getBlockByNumber':return {'number':hex(C['deployment_block']),'hash':H,'timestamp':'0x1'}
  if method=='eth_getCode':return self.code
  if method=='eth_getLogs':return self.logs
  if method=='eth_getTransactionReceipt':return {'status':'0x1','blockHash':H,'transactionHash':p[0],'logs':[l for l in self.logs if l['transactionHash']==p[0]]}
  if method=='eth_call':return {0:ENTRY0,1:ENTRY1}[int(p[0]['data'][10:],16)]
class Tests(unittest.TestCase):
 def test_wrong_runtime_is_unknown(self):
  meta,state=m.collect_canary(C,Chain('0x01',[ARMED]),None,1);self.assertEqual(meta['status'],'unknown');self.assertIn('runtime mismatch',meta['error']);self.assertEqual(meta['entries'],[]);self.assertIsNone(state)
 def test_burned_entry_decoded_as_burned(self):
  c=copy.deepcopy(C);c['runtime_sha256']=hashlib.sha256(b'\x01').hexdigest()
  meta,state=m.collect_canary(c,Chain('0x01',[ARMED,ARMED1,BURNED]),None,1);self.assertEqual(meta['status'],'observed');self.assertTrue(meta['coverage']['events_complete'])
  live,burned=meta['entries'];self.assertEqual((live['kind'],live['pot_wei'],live['until'],live['burned'],live['funder']),('Forgery','10000000000000000','1800731481',False,'0x97883cb4b2f21530277f86490d8881654e36e6aa'));self.assertEqual(live['cdhash'],'0x9e733cee03debdd1080c9de6f1a3cdd23fdacdfb74c15fd48c8fe02069d62bb8')
  self.assertTrue(burned['burned']);self.assertEqual(burned['pot_wei'],'0')
  b=meta['events'][2];self.assertEqual((b['event'],b['id'],b['claimant'],b['amount_wei']),('Burned','1','0x'+'0'*38+'c1','5'))
if __name__=='__main__':unittest.main()
