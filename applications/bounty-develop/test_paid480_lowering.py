"""Offline actual-public-byte lowering; claim/IDs are explicit synthetic fixtures."""
import copy,hashlib,importlib.util,json,pathlib,sys,tempfile,unittest
HERE=pathlib.Path(__file__).parent;ROOT=HERE.parents[1]
sys.path[:0]=[str(HERE),str(ROOT/'applications/bounty-runtime'),str(ROOT/'base-vm/browser-sandbox-v1/source/runner-content/lib')]
import paid480_inputs as h
import generation480_delivery as delivery
from audit_stage import audit,SLOTS
from dsmack_compose_contract.manifest import validate_manifest_bytes
sha=lambda b:hashlib.sha256(b).hexdigest()
canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
DATA=HERE/'fixtures/paid480'
class Controls(unittest.TestCase):
 def setUp(self):
  paths={'policy':DATA/'policy.json','terms':DATA/'terms.json','qualified_base':DATA/'originals/qualified-base.json'};self.docs={k:p.read_bytes()for k,p in paths.items()};self.config=canonical({'schema':'dsmack-paid480-requester-selection/1','files':{k:{'path':str(p.resolve()),'bytes':len(self.docs[k]),'sha256':sha(self.docs[k])}for k,p in paths.items()}});self.selected=h.Selected(self.config,sha(self.config),self.docs)
  self.claim={'task_id':h.TASK_ID,'attempt_id':sha(b'OFFLINE synthetic claim')[:32],'attempt_nonce':sha(b'OFFLINE synthetic nonce'),'payee':'0x0923ed168ed888098815c4e08e48e5caeecedadb'};self.ids={n:sha(('OFFLINE '+n).encode())[:32]for n in self.selected.a.STAGES};self.policy=json.loads(self.docs['policy']);self.plan=canonical(self.selected.plan(self.claim,self.policy['specification'],self.ids));self.base=(DATA/'originals/source_manifest').read_bytes();self.bundle=(DATA/'originals/source_bundle').read_bytes();self.driver=(ROOT/'applications/bounty-runtime/driver.py').read_bytes()
 def stage(self,i):return self.selected.assemble(self.plan,sha(self.plan),'generate-'+str(i),self.driver,self.base,self.bundle)
 def audited(self,stage):
  with tempfile.TemporaryDirectory()as root:
   root=pathlib.Path(root)
   for n,b in stage['files'].items():(root/n).write_bytes(b)
   return audit({n:root/n if n!='suite'else None for n in SLOTS},stage['request_sha256'],stage['stage_profile_sha256'],sha(self.driver),sha(self.plan))
 def test_three_actual_public_requests_lower_validate_and_bind480(self):
  m=delivery.selected('prepare');ref=json.loads((DATA/'originals/reference-manifest.json').read_bytes())
  for i in (1,2,3):
   stage=self.stage(i);result=self.audited(stage);m.generation_request(result,self.policy['specification']['sha256']);manifest,_=m.generation_manifest(ref,stage['files'],[stage['request_sha256'],stage['stage_profile_sha256'],sha(self.driver),sha(self.plan)]);validate_manifest_bytes(canonical(manifest));service=json.loads(manifest['docker_compose_file'])['services']['generate'];self.assertEqual(service['image'].split('@')[1],delivery.IMAGE);self.assertEqual(manifest['limits']['timeout_s'],550);self.assertEqual(result['request']['judge_index'],i);self.assertIsNone(result['request']['input_suite_sha256']);self.assertEqual(self.policy['resources']['runtime_seconds'],600)
 def test_old_oci_source_or_subject_refused(self):
  m=delivery.selected('prepare');r=self.audited(self.stage(1));spec=self.policy['specification']['sha256']
  for key,value in [('oci_manifest_sha256','d91250b5d024b5b995de52e20eba57ba48f01e9562bec4562d1f88702d2d675c'),('task_id','board-search-opus48-transport-v2-substring-v1')]:
   wrong=copy.deepcopy(r);wrong['request'][key]=value
   with self.assertRaises(ValueError):m.generation_request(wrong,spec)
  wrong=copy.deepcopy(r);p=json.loads(wrong['input_bytes']['acceptance_profile']);p['acceptance']['judge_generation']['generator_source_sha256']='5285751bb2ca25fb4dd72dfb6e3f0467eba101166b3066a4646a412448f61973';wrong['input_bytes']['acceptance_profile']=canonical(p)
  with self.assertRaises(ValueError):m.generation_request(wrong,spec)
 def test_missing_actual_claim_and_old_documents_refused(self):
  with self.assertRaises(ValueError):self.selected.claim(None)
  wrong=dict(self.docs);wrong['policy']=(DATA/'originals/policy.json').read_bytes()
  with self.assertRaises(ValueError):h.Selected(self.config,sha(self.config),wrong)
 def test_no_candidate_input_to_generation(self):
  with self.assertRaises(ValueError):self.selected.assemble(self.plan,sha(self.plan),'generate-1',self.driver,self.base,self.bundle,candidate_manifest=self.base,candidate_bundle=self.bundle)
 def test_builder_is_exact_new_image_and_config(self):
  m=delivery.selected('build');self.assertEqual(m.IMAGE,delivery.IMAGE);self.assertEqual(m.CONFIG,delivery.CONFIG)
if __name__=='__main__':unittest.main()
