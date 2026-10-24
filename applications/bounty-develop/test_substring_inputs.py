"""Synthetic claims test public lowering only; no actual claim/provider work."""
from pathlib import Path
import copy,hashlib,importlib.util,json,unittest
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('substring_inputs',HERE/'substring_inputs.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
c=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
sha=lambda b:hashlib.sha256(b).hexdigest()
class Tests(unittest.TestCase):
 def setUp(self):
  names={'policy':'acceptance-policy.json','terms':'task-terms.json','qualified_base':'qualified-base.json'}
  self.docs={k:(HERE/'fixtures/substring'/v).read_bytes()for k,v in names.items()};self.config={'schema':'dsmack-substring-requester-selection/1','files':{k:{'path':str(HERE/'fixtures/substring'/names[k]),'bytes':len(b),'sha256':sha(b)}for k,b in self.docs.items()}};self.raw=c(self.config)
  self.claim={'task_id':m.TASK_ID,'attempt_id':'11'*16,'attempt_nonce':'22'*32,'payee':'0x0923ed168ed888098815c4e08e48e5caeecedadb'}
 def selected(self,docs=None,config=None,case=m.CASE):
  raw=c(config)if config is not None else self.raw;return m.Selected(raw,sha(raw),self.docs if docs is None else docs,case)
 def bad(self,fn):
  with self.assertRaises((ValueError,KeyError,TypeError)):fn()
 def test_actual_new_documents(self):
  x=self.selected();self.assertEqual(x.c.parse(x.policy)['specification']['sha256'],m.SPEC);self.assertEqual(x.c.sha(x.terms),m.PINS['terms'])
 def test_missing_actual_claim_refuses(self):self.bad(lambda:self.selected().claim(None))
 def test_old_subject_refuses(self):
  for old in ['board-search-opus48-transport-v2','board-search-opus48-transport-v2-repeat-2']:
   cl={**self.claim,'task_id':old};self.bad(lambda:self.selected().claim(cl))
 def test_other_case_refuses(self):
  for case in ['first','second','repeat-2','substring-extra']:self.bad(lambda:self.selected(case=case))
 def test_wrong_old_policy_refuses_even_rebound_descriptor(self):
  old=copy.deepcopy(self.docs);v=json.loads(old['policy']);v['policy_id']='board-search-opus48-transport-v2';old['policy']=c(v);cfg=copy.deepcopy(self.config);cfg['files']['policy'].update(bytes=len(old['policy']),sha256=sha(old['policy']));self.bad(lambda:self.selected(old,cfg))
 def test_wrong_base_refuses_even_rebound_descriptor(self):
  old=copy.deepcopy(self.docs);v=json.loads(old['qualified_base']);v['base_vm_os_image_hash']='ab'*32;old['qualified_base']=c(v);cfg=copy.deepcopy(self.config);cfg['files']['qualified_base'].update(bytes=len(old['qualified_base']),sha256=sha(old['qualified_base']));self.bad(lambda:self.selected(old,cfg))
 def test_wrong_selection_hash_refuses(self):self.bad(lambda:m.Selected(self.raw,'ab'*32,self.docs))
 def test_missing_or_extra_document_refuses(self):
  for k in ['policy','terms','qualified_base']:
   d=dict(self.docs);d.pop(k);self.bad(lambda:self.selected(d))
  d={**self.docs,'extra':b'{}'};self.bad(lambda:self.selected(d))
 def test_synthetic_develop_and_full_blind_plan(self):
  x=self.selected();manifest=(HERE/'fixtures/transport-v2/base-manifest.json').read_bytes();bundle=(HERE/'fixtures/transport-v2/base-source.tar').read_bytes();driver=(HERE/'driver.py').read_bytes();dev=x.develop(self.claim,'33'*16,driver,manifest,bundle);request=json.loads(dev['files']['request']);self.assertIsNone(request['candidate']);self.assertEqual(request['task_id'],m.TASK_ID);self.assertEqual(json.loads(dev['files']['stage_profile'])['specification']['sha256'],m.SPEC)
  ids={stage:format(i,'032x')for i,stage in enumerate(x.a.STAGES,1)};spec=json.loads(x.policy)['specification'];plan=x.plan(self.claim,spec,ids);self.assertEqual(plan['limits']['generation_count'],3);self.assertEqual(plan['acceptance']['candidate_outcome'],'all-three-pass');self.assertEqual(plan['claim']['task_id'],m.TASK_ID)
 def test_synthetic_generation_lowering_has_new_spec(self):
  x=self.selected();ids={stage:format(i,'032x')for i,stage in enumerate(x.a.STAGES,1)};plan=c(x.plan(self.claim,json.loads(x.policy)['specification'],ids));manifest=(HERE/'fixtures/transport-v2/base-manifest.json').read_bytes();bundle=(HERE/'fixtures/transport-v2/base-source.tar').read_bytes();driver=(HERE.parent/'bounty-runtime/driver.py').read_bytes();out=x.assemble(plan,sha(plan),'generate-1',driver,manifest,bundle);self.assertEqual(json.loads(out['files']['stage_profile'])['specification']['sha256'],m.SPEC);self.assertEqual(json.loads(out['files']['request'])['task_id'],m.TASK_ID)
 def test_old_module_namespace_untouched(self):
  x=self.selected();q=importlib.util.spec_from_file_location('unchanged_v2',HERE/'transport_v2_inputs.py');old=importlib.util.module_from_spec(q);q.loader.exec_module(old);self.assertEqual(old.IDS,{'first':'board-search-opus48-transport-v2','second':'board-search-opus48-transport-v2-repeat-2'});self.assertEqual(sha((HERE/'transport_v2_inputs.py').read_bytes()),m.LEGACY_SHA);self.bad(lambda:x.a.case_identity('repeat-2'))
if __name__=='__main__':unittest.main()
