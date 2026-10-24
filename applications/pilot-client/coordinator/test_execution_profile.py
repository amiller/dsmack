"""Selected profile controls: synthetic descriptors only, no VM/provider/auth."""
import copy,importlib.util,unittest
from pathlib import Path
S=importlib.util.spec_from_file_location('coordinator_profile',Path(__file__).with_name('coordinator.py'));d=importlib.util.module_from_spec(S);S.loader.exec_module(d)
class Profiles(unittest.TestCase):
 def setUp(self):
  self.spec={'workload_id':'bounty-board-search-browser-review-v1','profile':'mini-4096','runtime_seconds':600}
  self.inputs={'compose_manifest_path':{'sha256':'a'*64}}
  self.q={'schema':'dsmack-protected-execution-profile/1','profile_id':self.spec['workload_id'],'workload_id':self.spec['workload_id'],'resource_profile':'mini-4096','memory_mib':4096,'vcpus':1,'runtime_seconds':600,'scratch_template_bytes':4<<30,'result_template_bytes':256<<20,'compose_manifest_sha256':'a'*64,'model_profile':'synthetic-claude-profile-v1','security_preset':'synthetic-browser-network-none-v1'}
 def select(self,q=None,s=None):return d.execution_profile({'execution_profile':self.q if q is None else q},s or self.spec,self.inputs)
 def test_explicit_browser_role_split_and_codex_sample(self):
  self.assertEqual(self.select(),(4<<30,256<<20,4<<30))
  q=copy.deepcopy(self.q);q.update(profile_id='codex-private-sample',workload_id='codex-private-sample',scratch_template_bytes=1<<30)
  s={**self.spec,'workload_id':'codex-private-sample'}
  self.assertEqual(self.select(q,s),(1<<30,256<<20,1<<30))
 def test_closed_develop_profile_scratch_cap_preserved(self):
  q={**self.q,'profile_id':'bounty-board-search-develop-v1','workload_id':'bounty-board-search-develop-v1','model_profile':'claude-opus-4-8','security_preset':'none'};spec={**self.spec,'workload_id':q['workload_id']}
  self.assertEqual(self.select(q,spec),(4<<30,256<<20,4<<30))
  for k,v in [('model_profile','other'),('security_preset','browser-sandbox-v1')]:
   with self.assertRaises(d.Refused):self.select({**q,k:v},spec)
 def test_generate_is_distinct_closed_workload(self):
  q={**self.q,'profile_id':'bounty-board-search-generate-v1','workload_id':'bounty-board-search-generate-v1','model_profile':'claude-opus-4-8','security_preset':'none'};spec={**self.spec,'workload_id':q['workload_id']}
  self.assertEqual(self.select(q,spec),(4<<30,256<<20,4<<30))
  for k,v in [('model_profile','other'),('security_preset','browser-sandbox-v1'),('workload_id','bounty-board-search-develop-v1')]:
   with self.assertRaises(d.Refused):self.select({**q,k:v},spec)
 def test_diagnostic_tuple_is_separate(self):
  q={**self.q,'profile_id':'claude-broker-diagnostic-v1','workload_id':'claude-broker-diagnostic-v1','model_profile':'none','security_preset':'none'};spec={**self.spec,'workload_id':q['workload_id']}
  self.assertEqual(self.select(q,spec),(4<<30,256<<20,4<<30))
  for k,v in [('model_profile','claude-opus-4-8'),('security_preset','browser-sandbox-v1'),('workload_id','bounty-board-search-generate-v1')]:
   with self.assertRaises(d.Refused):self.select({**q,k:v},spec)
 def test_no_extension_preserves_historical_profile_only(self):
  s={**self.spec,'workload_id':'claude-coding-task-subscription-dstack'}
  self.assertEqual(d.execution_profile({},s,self.inputs),(1<<30,256<<20,1<<30))
  with self.assertRaises(d.Refused):d.execution_profile({},self.spec,self.inputs)
  with self.assertRaises(d.Refused):d.execution_profile({'execution_profile':None},s,self.inputs)
 def test_policy_or_descriptor_cannot_expand_selected_envelope(self):
  for k,values in {'schema':['future'],'profile_id':['custom','claude-coding-task-subscription-dstack'],'workload_id':['other'],'resource_profile':['custom'],'memory_mib':[8192,True],'vcpus':[2,True],'runtime_seconds':[601,True],'scratch_template_bytes':[8<<30,True],'result_template_bytes':[2<<30,True],'compose_manifest_sha256':['b'*64],'model_profile':['','new model','../../config\n'],'security_preset':['','network any']}.items():
   for v in values:
    with self.subTest(key=k,value=v):
     q={**self.q,k:v}
     with self.assertRaises(d.Refused):self.select(q)
  for k,v in [('profile','other'),('runtime_seconds',599),('workload_id','other')]:
   with self.assertRaises(d.Refused):self.select(s={**self.spec,k:v})
  q={**self.q,'arbitrary_config':{}}
  with self.assertRaises(d.Refused):self.select(q)
  for k in self.q:
   q={**self.q};del q[k]
   with self.assertRaises(d.Refused):self.select(q)
 def test_credential_free_only_for_explicit_browser_none(self):
  self.assertFalse(d.credential_free_profile({}))
  self.assertFalse(d.credential_free_profile({'execution_profile':self.q}))
  q={**self.q,'model_profile':'none'}
  self.assertTrue(d.credential_free_profile({'execution_profile':q}))
  self.assertFalse(d.credential_free_profile({'execution_profile':{**q,'profile_id':'codex-private-sample'}}))
 def test_parser_default_stays_one_gib_result_never_expands(self):
  parser=d.modules()['session_parser']
  s={k:'/private/synthetic/'+k for k in parser.DOC_PATH_KEYS}
  s.update(schema=parser.V3_SESSION_SCHEMA,profile='mini-4096',workload_sha256='a'*64,workload_id=self.spec['workload_id'],runtime_seconds=600,private_input_path='',net_socket_path='',scratch_template_sha256='b'*64,result_template_sha256='c'*64,scratch_template_bytes=4<<30,result_template_bytes=256<<20)
  raw=parser.canonical_bytes(s)
  with self.assertRaises(parser.Refusal):parser.parse_session_bytes(raw)
  parser.parse_session_bytes(raw,scratch_max_bytes=4<<30)
  for cap in [True,8<<30,0]:
   with self.assertRaises(parser.Refusal):parser.parse_session_bytes(raw,scratch_max_bytes=cap)
  for k,n in [('result_template_bytes',2<<30),('scratch_template_bytes',(4<<30)+512),('scratch_template_bytes',(4<<30)-1)]:
   v={**s,k:n}
   with self.assertRaises(parser.Refusal):parser.parse_session_bytes(parser.canonical_bytes(v),scratch_max_bytes=4<<30)
if __name__=='__main__':unittest.main()
