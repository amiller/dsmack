"""Offline synthetic RPC/keys only. Never imports operational config or role files."""
import importlib.util,pathlib,tempfile,unittest,copy
spec=importlib.util.spec_from_file_location('worker',pathlib.Path(__file__).with_name('worker.py'));w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
CODE='0x'+pathlib.Path(__file__).with_name('fixtures').joinpath('WorkEscrow.runtime.hex').read_text().strip().removeprefix('0x')
SECRETS={role:bytes([i])*32 for i,role in enumerate(['allocator','execution','review','delivery'],1)}
ADDR={r:w.Account.from_key(v).address.lower()for r,v in SECRETS.items()};PAYEE=w.Account.from_key(bytes([7])*32).address.lower();REQUESTER='0x'+'1'*40
B={'schema':'dsmack-arcade-settlement-binding/1','attempt_id':'a'*32,'payee':PAYEE,'candidate_commit':'b'*40,'policy_sha256':'c'*64,'report_sha256':'d'*64,'candidate_sha256':'e'*64,'evidence_sha256':'f'*64,'delivery_sha256':'1'*64,'original_report_authenticated':True,'original_outputs_verified':True,'checker_recomputed':True,'delivery_rehashed':True}
def configuration(root):return {'schema':'dsmack-arcade-claim-worker/1','chain_id':84532,'contract':w.CONTRACT,'runtime_sha256':w.RUNTIME,'task_id':'10','task_created_block':'0x64','package_hash':'2'*64,'policy_hash':'c'*64,'payout_wei':'100000000000000','requester':REQUESTER,'journal_root':str(root),'max_allocator_fee_wei':'100000000000000','roles':{r:{'address':a,'key_file':'/not-operational/'+r}for r,a in ADDR.items()},'terms':{'adjudicator':ADDR['review'],'effort_pay':'0','completion_pay':'100000000000000','submit_seconds':21600,'review_seconds':86400,'adjudication_seconds':3600}}
def input(c):return {'task':{'task_id':'10','policy_sha256':'c'*64,'chain_id':84532,'contract':w.CONTRACT},'attempt':{'id':'a'*32,'payee':PAYEE,'candidate_commit':'b'*40,'state':'verified','verdict':{'accepted':True,'report_sha256':'d'*64}},'request_id':'offline-request-001'}
class Mock:
 def __init__(self,c):self.c=c;self.state=0;self.active=0;self.available=10**14;self.sent=[];self.pending=False;self.code=CODE;self.chain=84532;self.now=1000;self.bad_digest=False;self.withdrawn=False;self.resolve_outcome=2;self.credit=10**14;self.last_hash=None
 def task(self):
  c=self.c;return [REQUESTER,True,self.available,self.active,bytes.fromhex(c['package_hash']),bytes.fromhex(c['policy_hash']),*[ADDR[r]for r in ['allocator','execution','review','delivery']],ADDR['review'],0,10**14,21600,86400,3600]
 def assignment(self):return [10,PAYEE,self.state,10**14 if self.state in(1,2)else 0,5000,9000,*([bytes.fromhex(B[k])for k in ['candidate_sha256','evidence_sha256','delivery_sha256']]if self.state>=2 else[w.ZERO]*3)]
 def block(self):return {'number':'0x65','hash':'0x'+'5'*64,'timestamp':hex(self.now)}
 def event(self,kind):
  if kind=='assigned':topics=['0x'+w.keccak(text='Assigned(uint256,uint256,address,uint256,uint256)').hex(),hex(11),hex(10),'0x'+PAYEE[2:].rjust(64,'0')];types=['uint256','uint256'];values=[10**14,5000]
  elif kind=='resolved':topics=['0x'+w.keccak(text='Resolved(uint256,uint8,uint256)').hex(),'0x'+hex(11)[2:].rjust(64,'0')];types=['uint8','uint256'];values=[self.resolve_outcome,10**14]
  else:topics=['0x'+w.keccak(text='Withdrawn(address,uint256)').hex(),'0x'+PAYEE[2:].rjust(64,'0')];types=['uint256'];values=[10**14]
  return {'address':w.CONTRACT,'topics':topics,'data':'0x'+w.encode(types,values).hex(),'transactionIndex':'0x1'if kind=='withdrawn'else'0x0','logIndex':'0x1'if kind=='withdrawn'else'0x0','blockNumber':'0x65','blockHash':'0x'+'5'*64,'transactionHash':self.last_hash if kind=='assigned'else'0x'+('6'if kind=='resolved'else'7')*64}
 def __call__(self,m,a):
  if m=='eth_chainId':return hex(self.chain)
  if m=='eth_getBlockByNumber':return self.block()
  if m=='eth_getCode':return self.code
  if m=='eth_getTransactionCount':return '0x0'
  if m=='eth_estimateGas':return hex(100000)
  if m=='eth_gasPrice':return hex(1000)
  if m=='eth_getBalance':return hex(10**18)
  if m=='eth_sendRawTransaction':
   self.sent.append(a[0]);self.last_hash='0x'+w.keccak(bytes.fromhex(a[0][2:])).hex();self.state=1;self.active=11;self.available=0
   if self.pending:raise OSError('synthetic lost response')
   return self.last_hash
  if m=='eth_getTransactionReceipt':
   if self.pending:return None
   kind='assigned'if a[0]==self.last_hash else'resolved'if a[0]=='0x'+'6'*64 else'withdrawn';return {'status':'0x1','transactionHash':a[0],'to':w.CONTRACT,'from':ADDR['allocator']if kind=='assigned'else PAYEE,'blockNumber':'0x65','blockHash':'0x'+'5'*64,'logs':[self.event(kind)]}
  if m=='eth_getLogs':
   if a[0]['topics'][0]=='0x'+w.keccak(text='Resolved(uint256,uint8,uint256)').hex():return [self.event('resolved')]
   return [self.event('withdrawn')]if self.withdrawn else[]
  if m=='eth_call':
   x=a[0]['data'];selector=x[:10]
   if selector==w.data('task(uint256)',['uint256'],[10])[:10]:return '0x'+w.encode(w.TASK_TYPES,self.task()).hex()
   if selector==w.data('assignment(uint256)',['uint256'],[11])[:10]:return '0x'+w.encode(w.ASSIGN_TYPES,self.assignment()).hex()
   if selector==w.data('withdrawable(address)',['address'],[PAYEE])[:10]:return hex(self.credit)
   if selector==w.data('getL1Fee(bytes)',['bytes'],[b''])[:10]or selector==w.data('getOperatorFee(uint256)',['uint256'],[1])[:10]:return '0x1'
   if selector==w.data('decisionDigest(uint256,uint8)',['uint256','uint8'],[11,2])[:10]:
    if self.bad_digest:return '0x'+'0'*64
    b=w.Bridge(self.c,self,lambda _:dict(B),key_loader=lambda r:SECRETS[r]);msg=w.encode_typed_data(full_message=b.typed(11,input(self.c)['attempt'],B));return '0x'+w.keccak(b'\x19'+msg.version+msg.header+msg.body).hex()
  raise AssertionError((m,a))
class Tests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix="dsmack-claim-test-",dir=pathlib.Path.home());self.c=configuration(pathlib.Path(self.tmp.name)/'journal');self.rpc=Mock(self.c);self.reads=[];self.b=w.Bridge(self.c,self.rpc,lambda _:dict(B),key_loader=self.key)
 def tearDown(self):self.tmp.cleanup()
 def key(self,r):self.reads.append(r);return SECRETS[r]
 def process(self):return self.b.process(input(self.c))
 def test_assign_once_then_submit_only_no_oracle_signing(self):
  p=self.process();self.assertEqual(p['stage'],'submit');self.assertEqual(self.reads,['allocator']);self.assertEqual(len(self.rpc.sent),1);self.assertEqual(self.process()['stage'],'submit');self.assertEqual(len(self.rpc.sent),1)
 def test_lost_broadcast_response_only_observes_same_hash(self):
  self.rpc.pending=True;self.assertEqual(self.process()['stage'],'allocation_pending');self.assertEqual(len(self.rpc.sent),1);self.rpc.pending=False;self.assertEqual(self.process()['stage'],'submit');self.assertEqual(len(self.rpc.sent),1)
 def test_after_submitted_three_real_synthetic_signatures_and_digest(self):
  self.process();self.rpc.state=2;p=self.process();self.assertEqual(p['stage'],'resolve');self.assertEqual(len(p['signatures']),3);self.assertEqual(self.reads,['allocator','execution','review','delivery']);self.process();self.assertEqual(len(self.reads),4)
 def test_wrong_digest_commitment_or_expired_window_never_signs_roles(self):
  self.process();self.rpc.state=2;self.rpc.bad_digest=True
  with self.assertRaises(w.Refusal):self.process()
  self.assertEqual(self.reads,['allocator']);self.rpc.bad_digest=False;self.rpc.now=9001
  with self.assertRaises(w.Refusal):self.process()
  self.assertEqual(self.reads,['allocator'])
 def test_unfunded_wrong_runtime_wrong_chain_and_oldtask_refuse(self):
  for attr,value in [('available',0),('code','0x00'),('chain',1)]:
   old=getattr(self.rpc,attr);setattr(self.rpc,attr,value)
   with self.assertRaises(w.Refusal):self.process()
   setattr(self.rpc,attr,old)
  c=copy.deepcopy(self.c);c['task_id']='9'
  with self.assertRaises(w.Refusal):w.config_check(c)
  self.assertEqual(self.reads,[])
 def test_public_true_cannot_replace_common_validation(self):
  self.b.validate=lambda _:{**B,'checker_recomputed':False}
  with self.assertRaises(w.Refusal):self.process()
  self.assertEqual(self.reads,[])
 def test_payee_and_delivery_changes_refuse(self):
  self.b.validate=lambda _:{**B,'payee':REQUESTER}
  with self.assertRaises(w.Refusal):self.process()
  self.assertEqual(self.reads,[])
 def test_withdraw_only_after_real_completion_event_and_received_only_after_event(self):
  self.process();self.rpc.state=3;self.rpc.active=0;self.rpc.resolve_outcome=1
  with self.assertRaises(w.Refusal):self.process()
  self.rpc.resolve_outcome=2;self.assertEqual(self.process()['stage'],'withdraw');self.rpc.credit=0;self.assertEqual(self.process()['stage'],'withdrawal_unobserved');self.rpc.withdrawn=True;p=self.process();self.assertTrue(p['payment_received']);self.assertEqual(p['stage'],'received')
 def test_actual_runtime_validation_envelope_unwrapped_and_wrong_shapes_refused(self):
  self.assertEqual(w.validation_envelope(w.canon({'public_result':B,'artifacts':[]})),B)
  for invalid in [B,{'public_result':B,'artifacts':[{}]},{'public_result':B,'artifacts':[],'accepted':True}]:
   with self.assertRaises(w.Refusal):w.validation_envelope(w.canon(invalid))
 def test_cached_role_signature_corruption_is_not_published(self):
  self.process();self.rpc.state=2;self.process();j=self.b.journal('a'*32);p=next(j.glob('signatures-*.json'));v=w.parse(p.read_bytes());v['signatures'][0]='0x'+'0'*130;p.write_bytes(w.canon(v))
  with self.assertRaises(Exception):self.process()
 def test_busy_lock_refuses_before_chain_or_key_action(self):
  import os,fcntl
  fd=os.open(self.b.root/'.bridge.lock',os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   with self.assertRaises(w.Refusal):self.process()
   self.assertEqual(self.reads,[]);self.assertEqual(self.rpc.sent,[])
  finally:os.close(fd)
 def test_pullworker_invocation_contract_wraps_public_result_and_refuses_wrong_digest(self):
  import types
  hp=pathlib.Path(__file__).with_name('claim_handler.py');handler=types.ModuleType('handler');exec(compile(hp.read_bytes(),str(hp),'exec'),handler.__dict__)
  root=pathlib.Path(self.tmp.name);job=root/'job';job.mkdir(mode=0o700);cfg=root/'bridge.json';cfg.write_bytes(w.canon(self.c));cfg.chmod(0o600);binding={'state_dir':str(root),'claim_bridge':{'config':{'path':str(cfg),'bytes':cfg.stat().st_size,'sha256':w.sha(cfg.read_bytes())}}};v=input(self.c);request={'action':'claim','input':v,'job_dir':str(job),'input_sha256':w.sha(w.canon(v))}
  class Fake:
   def process(self,v):return {'stage':'synthetic-contract-only','payee':v['attempt']['payee']}
  result=handler.handle(request,binding,w,make_bridge=lambda _:Fake());self.assertEqual(set(result),{'public_result','artifacts'});self.assertEqual(result['artifacts'],[]);self.assertEqual(result['public_result']['payee'],PAYEE)
  with self.assertRaises(ValueError):handler.handle({**request,'input_sha256':'0'*64},binding,w,make_bridge=lambda _:Fake())
 def test_official_rpc_constant_user_agent_and_read_request_contract(self):
  from unittest.mock import patch
  requests=[]
  class Response:
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def read(self,cap):self.cap=cap;return w.canon({'jsonrpc':'2.0','id':1,'result':'0x14a34'})
  def open_request(request,timeout):requests.append((request,timeout));return Response()
  with patch.object(w.urllib.request,'urlopen',side_effect=open_request):self.assertEqual(w.RPC('https://sepolia.base.org')('eth_chainId',[]),'0x14a34')
  req,timeout=requests[0];self.assertEqual(req.get_header('User-agent'),'dsmack-arcade-pilot/1');self.assertEqual(req.get_header('Content-type'),'application/json');self.assertEqual(timeout,20);self.assertEqual(w.parse(req.data),{'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]})
if __name__=='__main__':unittest.main()
