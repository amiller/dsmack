"""Offline actual-public-byte lowering; claim/IDs are explicit synthetic fixtures."""
import argparse,copy,hashlib,importlib.util,json,pathlib,sys,tempfile,unittest
HERE=pathlib.Path(__file__).parent;ROOT=HERE.parents[1]
sys.path[:0]=[str(HERE),str(ROOT/'applications/bounty-runtime'),str(ROOT/'base-vm/browser-sandbox-v1/source/runner-content/lib')]
import serialization_inputs as h
import serialization_generation_delivery as delivery
from audit_stage import audit,SLOTS
from project import project
from dsmack_compose_contract.manifest import validate_manifest_bytes
sha=lambda b:hashlib.sha256(b).hexdigest()
canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
class Controls(unittest.TestCase):
 def setUp(self):
  paths={'policy':DATA/'policy.json','terms':DATA/'terms.json','qualified_base':ORIGINALS/'qualified-base.json'};self.docs={k:p.read_bytes()for k,p in paths.items()};self.config=canonical({'schema':'dsmack-serialization-paid480-requester-selection/1','files':{k:{'path':str(p.resolve()),'bytes':len(self.docs[k]),'sha256':sha(self.docs[k])}for k,p in paths.items()}});self.selected=h.Selected(self.config,sha(self.config),self.docs)
  self.claim={'task_id':h.TASK_ID,'attempt_id':sha(b'OFFLINE synthetic claim')[:32],'attempt_nonce':sha(b'OFFLINE synthetic nonce'),'payee':'0x0923ed168ed888098815c4e08e48e5caeecedadb'};self.ids={n:sha(('OFFLINE '+n).encode())[:32]for n in self.selected.a.STAGES};self.policy=json.loads(self.docs['policy']);self.plan=canonical(self.selected.plan(self.claim,self.policy['specification'],self.ids));self.base=(ORIGINALS/'source_manifest').read_bytes();self.bundle=(ORIGINALS/'source_bundle').read_bytes();self.driver=(ROOT/'applications/bounty-runtime/driver.py').read_bytes()
 def stage(self,i):return self.selected.assemble(self.plan,sha(self.plan),'generate-'+str(i),self.driver,self.base,self.bundle)
 def audited(self,stage):
  with tempfile.TemporaryDirectory()as root:
   root=pathlib.Path(root)
   for n,b in stage['files'].items():(root/n).write_bytes(b)
   return audit({n:root/n if n!='suite'else None for n in SLOTS},stage['request_sha256'],stage['stage_profile_sha256'],sha(self.driver),sha(self.plan))
 def test_three_actual_public_requests_lower_validate_and_bind480(self):
  m=delivery.selected('prepare');ref=json.loads((ORIGINALS/'reference-manifest.json').read_bytes())
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
  wrong=dict(self.docs);wrong['policy']=(ORIGINALS/'policy.json').read_bytes()
  with self.assertRaises(ValueError):h.Selected(self.config,sha(self.config),wrong)
 def test_no_candidate_input_to_generation(self):
  with self.assertRaises(ValueError):self.selected.assemble(self.plan,sha(self.plan),'generate-1',self.driver,self.base,self.bundle,candidate_manifest=self.base,candidate_bundle=self.bundle)
 def test_develop_gets_only_selected_guided_profile(self):
  driver=(HERE/'driver.py').read_bytes()
  stage=self.selected.develop(self.claim,sha(b'OFFLINE fresh DEV')[:32],driver,self.base,self.bundle)
  profile=json.loads(stage['files']['stage_profile'])
  self.assertEqual(sha(canonical(profile)),h.DEV_PROFILE)
  self.assertEqual(profile['specification']['sha256'],h.DEV_SPEC)
  self.assertIn('Implementation feedback',profile['specification']['text'])
  self.assertIsNone(json.loads(stage['files']['request'])['candidate'])
 def test_generation_prompt_inputs_exclude_dev_feedback_and_candidate(self):
  spec=self.policy['specification']
  self.assertNotIn('Implementation feedback',canonical(json.loads(self.plan)).decode())
  for i in (1,2,3):
   stage=self.stage(i);result=self.audited(stage)
   # Runtime generation consumes this closed stage profile and original base,
   # never the DEV profile from the enclosing policy.
   self.assertEqual(result['stage_profile'],{'schema':'dsmack-bounty-generation-stage-profile/1','specification':spec})
   self.assertEqual(stage['files']['source_bundle'],self.bundle)
   with tempfile.TemporaryDirectory()as root:
    public=pathlib.Path(root)/'public';project(result,public)
    self.assertEqual(sorted(x.name for x in public.iterdir()),['base.json','spec.txt'])
    self.assertEqual((public/'spec.txt').read_bytes(),spec['text'].encode())
    self.assertNotIn(b'Implementation feedback',(public/'base.json').read_bytes())
   self.assertNotIn('Implementation feedback',stage['files']['stage_profile'].decode())
   self.assertIsNone(result['request']['input_suite_sha256'])
  with self.assertRaises(ValueError):self.selected.plan(self.claim,self.policy['development']['profile']['specification'],self.ids)
 def test_altered_goal_guidance_profile_or_source_pin_refused(self):
  for field in ('global','guidance','profile'):
   p=copy.deepcopy(self.policy)
   if field=='global':p['specification']['text']+=' changed'
   elif field=='guidance':p['development']['profile']['specification']['text']+=' changed'
   else:p['development']['profile_sha256']='0'*64
   docs=dict(self.docs);docs['policy']=canonical(p)
   config=json.loads(self.config);config['files']['policy'].update(bytes=len(docs['policy']),sha256=sha(docs['policy']))
   raw=canonical(config)
   with self.assertRaises(ValueError):h.Selected(raw,sha(raw),docs)
  original=h.LEGACY_SHA
  try:
   h.LEGACY_SHA='0'*64
   with self.assertRaises(ValueError):h.Selected(self.config,sha(self.config),self.docs)
  finally:h.LEGACY_SHA=original
 def test_serialization_contract_refuses_missing_or_altered_representation(self):
  m=delivery.selected('prepare');r=self.audited(self.stage(1));spec=self.policy['specification']['sha256']
  for change in ('missing','version','raw'):
   wrong=copy.deepcopy(r);p=json.loads(wrong['input_bytes']['acceptance_profile'])
   if change=='missing':p['acceptance']['judge_generation'].pop('serialization')
   elif change=='version':p['acceptance']['judge_generation']['serialization']['version']='unreviewed/2'
   else:p['acceptance']['judge_generation']['serialization']['raw_artifact']='canonical-disguised-as-raw.json'
   wrong['input_bytes']['acceptance_profile']=canonical(p)
   with self.assertRaises(ValueError):m.generation_request(wrong,spec)
 def test_same_goal_and_guidance_new_runtime_evidence_contract(self):
  self.assertEqual(self.policy['specification']['sha256'],h.SPEC)
  self.assertEqual(self.policy['development']['profile']['specification']['sha256'],h.DEV_SPEC)
  self.assertEqual(h.SERIALIZATION,delivery.SERIALIZATION)
  self.assertEqual(h.SERIALIZATION['version'],'strict-json-canonical-suite/1')
  self.assertEqual(h.SERIALIZATION['raw_artifact'],'suite-model-raw.txt')
  recipe=json.loads((ROOT/'applications/bounty-judges/generation-recipe-serialization.json').read_bytes())
  self.assertEqual(recipe['serialization'],h.SERIALIZATION)
  self.assertEqual(len(recipe['required_success_outputs']),11)
  self.assertEqual(recipe['generator_source_sha256'],'e761cf4509069c4c6f4ffe545ea7a1546b4f5bd87dee03671e3434370f5886b7')
 def test_builder_is_exact_new_image_and_config(self):
  m=delivery.selected('build');self.assertEqual(m.IMAGE,delivery.IMAGE);self.assertEqual(m.CONFIG,delivery.CONFIG)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--data',type=pathlib.Path,default=HERE/'fixtures/serialization-paid480');a=ap.parse_args();DATA=a.data;ORIGINALS=HERE/'fixtures/paid480/originals';unittest.main(argv=[sys.argv[0]])
