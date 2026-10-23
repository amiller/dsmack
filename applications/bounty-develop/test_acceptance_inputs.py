"""Synthetic byte assembly controls; no execution/admission authority."""
import io,json,pathlib,sys,tarfile,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import acceptance_inputs as a
class Tests(unittest.TestCase):
 def setUp(self):
  self.spec={'text':'synthetic','sha256':a.sha(b'synthetic')};self.terms=a.canonical({'repo':'amiller/bounty-arcade','base_commit':'b'*40});self.policy=a.canonical({'specification':self.spec});self.driver=b'synthetic driver'
  self.patches=[patch.object(a,'TERMS',a.sha(self.terms)),patch.object(a,'POLICY',a.sha(self.policy)),patch.object(a,'DRIVER',a.sha(self.driver))]
  for p in self.patches:p.start();self.addCleanup(p.stop)
  self.claim={'task_id':'board-search-opus48-pilot-v1','attempt_id':'a'*32,'attempt_nonce':'b'*64,'payee':'0x'+'c'*40};self.runs={n:format(i+1,'032x')for i,n in enumerate(a.STAGES)}
  self.manifest,self.bundle,self.tree=self.source(b'base');self.addCleanup(patch.stopall);patch.object(a,'BASE',self.tree).start()
  self.plan=a.canonical(a.plan(self.terms,self.policy,self.claim,self.spec,self.runs));self.args=[self.plan,a.sha(self.plan),'generate-1',self.terms,self.policy,self.driver,self.manifest,self.bundle]
 def source(self,content):
  rows=[{'path':p,'mode':420,'bytes':len(content),'sha256':a.sha(content)}for p in a.source.BOARD];raw=a.canonical(rows);b=io.BytesIO()
  with tarfile.open(fileobj=b,mode='w',format=tarfile.USTAR_FORMAT)as t:
   for r in rows:
    x=tarfile.TarInfo(r['path']);x.mode=420;x.size=len(content);x.uid=x.gid=x.mtime=0;t.addfile(x,io.BytesIO(content))
  return raw,b.getvalue()[:1024+sum(512+((r['bytes']+511)//512)*512 for r in rows)],a.p.tree_digest(rows)
 def test_three_generators_are_candidate_blind_and_distinct(self):
  for i in(1,2,3):
   args=list(self.args);args[2]='generate-'+str(i);v=a.assemble(*args);r=json.loads(v['files']['request']);self.assertEqual(len(v['files']),8);self.assertEqual(r['run_id'],self.runs[args[2]]);self.assertNotIn('candidate',json.loads(v['files']['plan']));self.assertIsNone(v['relation'])
 def test_generation_refuses_candidate_and_suite(self):
  for kw in ({'candidate_manifest':self.manifest},{'suite_raw':b'{}'},{'expected_suite_sha':'0'*64}):
   with self.assertRaises(ValueError):a.assemble(*self.args,**kw)
 def test_reject_duplicate_ids_assignment_reuse_and_unselected_spec(self):
  for runs,spec in (({**self.runs,'generate-1':self.runs['base-1']},self.spec),({**self.runs,'generate-1':self.claim['attempt_id']},self.spec),(self.runs,{'text':'other','sha256':a.sha(b'other')})):
   with self.assertRaises(ValueError):a.plan(self.terms,self.policy,self.claim,spec,runs)
 def test_ci_requires_full_relation_and_selected_suite(self):
  cm,cb,tree=self.source(b'candidate');suite=b'{"schema":"dsmack-bounty-browser-suite/1","tests":[{"id":"synthetic","steps":[{"op":"navigate","path":"/apps/board/"},{"op":"assert_visible","selector":"body","value":true}]}]}';args=list(self.args);args[2]='candidate-1'
  with self.assertRaises(ValueError):a.assemble(*args,candidate_manifest=cm,candidate_bundle=cb,suite_raw=suite,expected_suite_sha='0'*64)
  v=a.assemble(*args,candidate_manifest=cm,candidate_bundle=cb,suite_raw=suite,expected_suite_sha=a.sha(suite));self.assertEqual(len(v['files']),9);self.assertEqual(v['source_tree_sha256'],tree);self.assertEqual(v['relation']['schema'],'dsmack-bounty-admission-transform/2')
 def test_base_profile_does_not_disclose_candidate_identity(self):
  cm,cb,tree=self.source(b'candidate');suite=b'{"schema":"dsmack-bounty-browser-suite/1","tests":[{"id":"synthetic","steps":[{"op":"navigate","path":"/apps/board/"},{"op":"assert_visible","selector":"body","value":true}]}]}';args=list(self.args);args[2]='base-1';v=a.assemble(*args,candidate_manifest=cm,candidate_bundle=cb,suite_raw=suite,expected_suite_sha=a.sha(suite));profile=json.loads(v['files']['stage_profile']);self.assertEqual(profile,{'schema':'dsmack-bounty-base-review-stage-profile/1','base_tree_manifest_sha256':self.tree});self.assertNotIn(tree,v['files']['stage_profile'].decode());self.assertEqual(v['relation']['candidate_tree_manifest_sha256'],tree)
 def test_primary_original_delivery_and_transform(self):
  cm,cb,tree=self.source(b'candidate');args=list(self.args);args[2]='primary-review';v=a.assemble(*args,candidate_manifest=cm,candidate_bundle=cb);r=json.loads(v['files']['request']);self.assertEqual(v['files']['source_bundle'],cb);self.assertEqual(r['candidate']['tree_manifest_sha256'],tree);self.assertEqual(r['required_artifacts'],a.ARTIFACTS)
 def test_all_ten_packets_pass_existing_application_auditor(self):
  import audit_stage
  cm,cb,tree=self.source(b'candidate');suite=b'{"schema":"dsmack-bounty-browser-suite/1","tests":[{"id":"synthetic","steps":[{"op":"navigate","path":"/apps/board/"},{"op":"assert_visible","selector":"body","value":true}]}]}'
  for stage in a.STAGES:
   args=list(self.args);args[2]=stage;kw={}if stage.startswith('generate-')else{'candidate_manifest':cm,'candidate_bundle':cb}
   if stage.startswith(('base-','candidate-')):kw.update(suite_raw=suite,expected_suite_sha=a.sha(suite))
   v=a.assemble(*args,**kw)
   with tempfile.TemporaryDirectory()as d:
    paths={k:None for k in audit_stage.SLOTS}
    for n,raw in v['files'].items():paths[n]=pathlib.Path(d)/n;paths[n].write_bytes(raw)
    result=audit_stage.audit(paths,v['request_sha256'],v['stage_profile_sha256'],a.DRIVER,a.sha(self.plan));self.assertEqual(result['role'],'primary-review'if stage=='primary-review'else stage.split('-')[0])
 def test_mutated_plan_policy_is_refused_even_under_its_own_hash(self):
  v=json.loads(self.plan);v['limits']['tests_per_suite']=99;raw=a.canonical(v);args=[raw,a.sha(raw),*self.args[2:]]
  with self.assertRaises(ValueError):a.assemble(*args)

class RepeatTests(Tests):
 def repeat_plan(self):
  terms=a.canonical({'repo':'amiller/bounty-arcade','base_commit':'b'*40,'case':'repeat-2'})
  claim={**self.claim,'task_id':'board-search-opus48-pilot-v1-repeat-2'}
  with patch.object(a,'REPEAT_TERMS',a.sha(terms)):
   raw=a.canonical(a.plan(terms,self.policy,claim,self.spec,self.runs,case='repeat-2'))
  return terms,claim,raw
 def test_first_default_bytes_unchanged(self):
  self.assertNotIn('case',json.loads(self.plan));self.assertEqual(self.plan,a.canonical(a.plan(self.terms,self.policy,self.claim,self.spec,self.runs,case='first')))
 def test_repeat_all_ten_stages_and_blind_generation(self):
  terms,claim,raw=self.repeat_plan();cm,cb,_=self.source(b'candidate');suite=b'{"schema":"dsmack-bounty-browser-suite/1","tests":[{"id":"synthetic","steps":[{"op":"navigate","path":"/apps/board/"},{"op":"assert_visible","selector":"body","value":true}]}]}'
  with patch.object(a,'REPEAT_TERMS',a.sha(terms)):
   for stage in a.STAGES:
    kw={}if stage.startswith('generate-')else dict(candidate_manifest=cm,candidate_bundle=cb)
    if stage.startswith(('base-','candidate-')):kw.update(suite_raw=suite,expected_suite_sha=a.sha(suite))
    v=a.assemble(raw,a.sha(raw),stage,terms,self.policy,self.driver,self.manifest,self.bundle,**kw);r=json.loads(v['files']['request'])
    self.assertEqual(r['task_id'],claim['task_id']);self.assertEqual(r['task_terms_sha256'],a.sha(terms));self.assertEqual(r['run_id'],self.runs[stage])
    if stage.startswith('generate-'):self.assertIsNone(v['relation']);self.assertNotIn('candidate',json.loads(raw))
 def test_case_not_inferred_from_task_or_terms(self):
  terms,claim,raw=self.repeat_plan()
  with patch.object(a,'REPEAT_TERMS',a.sha(terms)):
   for case in (None,'other','first'):
    with self.assertRaises(ValueError):a.plan(terms,self.policy,claim,self.spec,self.runs,case=case)
   for change in ({'case':None},{'case':'other'},{'case':'first'},{'task_terms_sha256':a.TERMS},{'claim':self.claim}):
    bad=a.canonical({**json.loads(raw),**change})
    with self.assertRaises(ValueError):a.selected_plan(bad,a.sha(bad))
   with self.assertRaises(ValueError):a.plan(self.terms,self.policy,self.claim,self.spec,self.runs,case='repeat-2')

if __name__=='__main__':unittest.main()
