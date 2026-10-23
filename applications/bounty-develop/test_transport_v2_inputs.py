"""Public old-base fixtures + unmistakably SYNTHETIC V2 descriptor/claims only."""
import io,json,pathlib,sys,tarfile,unittest
sys.path[:0]=[str(pathlib.Path(__file__).resolve().parent),str(pathlib.Path(__file__).resolve().parents[1]/'bounty-runtime')]
import transport_v2_inputs as v
R=pathlib.Path(__file__).resolve().parent;F=R/'fixtures/transport-v2';c=v.load('reference/transport_v2_policy.py')
def fixture():
 originals={n:(F/('original-'+n+'.json')).read_bytes()for n in ('policy','first','second')};b=c.canonical({'schema':'dsmack-qualified-broker-timeout-base/1','original_base_sha256':c.OLD_BASE,'base_vm_os_image_hash':c.sha(b'SYNTHETIC-NOT-QUALIFIED-BASE'),'source_derivation_sha256':c.sha(b'SYNTHETIC-DERIVATION'),'qualification_review_sha256':c.sha(b'SYNTHETIC-REVIEW'),'sentinel_source_sha256':c.SENTINEL});derived=c.construct(b,c.sha(b),originals);docs={'qualified_base':b,**{'original_'+n:raw for n,raw in originals.items()},'policy':derived['acceptance-policy.json'],'first_terms':derived['first-task-terms.json'],'second_terms':derived['second-task-terms.json']};config=c.canonical({'schema':'dsmack-transport-v2-funding-selection/1','files':{n:{'path':'/SYNTHETIC/'+n,'bytes':len(raw),'sha256':c.sha(raw)}for n,raw in docs.items()}});return config,docs
class Tests(unittest.TestCase):
 def setUp(self):
  self.raw,self.docs=fixture();self.bm=(F/'base-manifest.json').read_bytes();self.bb=(F/'base-source.tar').read_bytes()
 def select(self,case):return v.Selected(self.raw,c.sha(self.raw),self.docs,case)
 def claim(self,case):return {'task_id':v.IDS[case],'attempt_id':'a'*32,'attempt_nonce':'b'*64,'payee':'0x0923ed168ed888098815c4e08e48e5caeecedadb'}
 def candidate(self,s):
  rows,files=s.a.source.decode_source(self.bb,self.bm,s.a.BASE);files=dict(files);files['apps/board/logic.js']+=b'\n// synthetic relation only\n';rows=[{**r,'bytes':len(files[r['path']]),'sha256':c.sha(files[r['path']])}for r in rows];b=io.BytesIO()
  with tarfile.open(fileobj=b,mode='w',format=tarfile.USTAR_FORMAT)as t:
   for r in rows:
    x=tarfile.TarInfo(r['path']);x.mode=r['mode'];x.size=r['bytes'];x.uid=x.gid=x.mtime=0;t.addfile(x,io.BytesIO(files[r['path']]))
  length=1024+sum(512+((r['bytes']+511)//512)*512 for r in rows);return c.canonical(rows),b.getvalue()[:length]
 def test_both_cases_all_ten_audits_without_legacy_mutation(self):
  legacy=v.load('acceptance_inputs.py');old=(legacy.POLICY,legacy.TERMS)
  import audit_stage
  for case in v.IDS:
   s=self.select(case);runs={n:format(i+1,'032x')for i,n in enumerate(s.a.STAGES)};plan=c.canonical(s.plan(self.claim(case),c.parse(s.policy)['specification'],runs));cm,cb=self.candidate(s);suite=b'{"schema":"dsmack-bounty-browser-suite/1","tests":[{"id":"synthetic","steps":[{"op":"navigate","path":"/apps/board/"},{"op":"assert_visible","selector":"body","value":true}]}]}';driver=(R.parent/'bounty-runtime/driver.py').read_bytes()
   for stage in s.a.STAGES:
    kw={}if stage.startswith('generate-')else{'candidate_manifest':cm,'candidate_bundle':cb}
    if stage.startswith(('base-','candidate-')):kw.update(suite_raw=suite,expected_suite_sha=c.sha(suite))
    result=s.assemble(plan,c.sha(plan),stage,driver,self.bm,self.bb,**kw);request=c.parse(result['files']['request']);self.assertEqual(request['task_id'],v.IDS[case]);self.assertEqual(request['task_terms_sha256'],c.sha(s.terms));self.assertEqual(request['acceptance_profile_sha256'],c.sha(s.policy))
    if stage.startswith('generate-'):self.assertNotIn('candidate',c.parse(plan));self.assertNotIn(s.a.p.tree_digest(c.parse(cm)),plan.decode());self.assertIsNone(result['relation'])
    import tempfile
    with tempfile.TemporaryDirectory()as d:
     paths={n:None for n in audit_stage.SLOTS}
     for n,b in result['files'].items():paths[n]=pathlib.Path(d)/n;paths[n].write_bytes(b)
     self.assertEqual(audit_stage.audit(paths,result['request_sha256'],result['stage_profile_sha256'],c.sha(driver),c.sha(plan))['role'],'primary-review'if stage=='primary-review'else stage.split('-')[0])
  self.assertEqual((legacy.POLICY,legacy.TERMS),old)
 def test_fresh_develop_full_source_and_existing_core_audit(self):
  import core,tempfile
  for case in v.IDS:
   s=self.select(case);result=s.develop(self.claim(case),'e'*32,(R/'driver.py').read_bytes(),self.bm,self.bb);request=c.parse(result['files']['request']);self.assertIsNone(request['candidate']);self.assertEqual(request['base']['tree_manifest_sha256'],s.a.BASE)
   with tempfile.TemporaryDirectory()as d:
    paths={n:None for n in core.SLOTS}
    for n,b in result['files'].items():paths[n]=pathlib.Path(d)/n;paths[n].write_bytes(b)
    self.assertEqual(core.audit(paths,result['request_sha256'],result['stage_profile_sha256'],c.sha(result['files']['driver']),result['plan_sha256'])['role'],'develop')
 def test_wrong_case_legacy_claim_and_selection_hash_refuse(self):
  with self.assertRaises(ValueError):v.Selected(self.raw,'0'*64,self.docs,'first')
  with self.assertRaises(ValueError):self.select('other')
  s=self.select('first')
  for claim in [self.claim('second'),{**self.claim('first'),'task_id':'board-search-opus48-pilot-v1'},{**self.claim('first'),'payee':'0x'+'0'*40}]:
   with self.assertRaises(ValueError):s.claim(claim)
 def test_unapproved_policy_and_base_descriptor_refuse(self):
  for name in ('policy','qualified_base','first_terms'):
   docs=dict(self.docs);docs[name]+=b' ';config=c.parse(self.raw);config['files'][name].update(bytes=len(docs[name]),sha256=c.sha(docs[name]));raw=c.canonical(config)
   with self.assertRaises(ValueError):v.Selected(raw,c.sha(raw),docs,'first')
 def test_develop_execution_reuse_and_driver_change_refuse(self):
  s=self.select('first')
  for run,driver in [('a'*32,(R/'driver.py').read_bytes()),('e'*32,b'changed')]:
   with self.assertRaises(ValueError):s.develop(self.claim('first'),run,driver,self.bm,self.bb)
if __name__=='__main__':unittest.main()
