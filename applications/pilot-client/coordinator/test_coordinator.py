"""Synthetic temp controls only. No Mini, genuine approvals, signing or private data."""
import base64,copy,hashlib,importlib.util,json,os,plistlib,shutil,subprocess,tempfile,unittest
from pathlib import Path
S=importlib.util.spec_from_file_location('driver',Path(__file__).with_name('coordinator.py'));d=importlib.util.module_from_spec(S);S.loader.exec_module(d)
def digest(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while True:
   b=f.read(1048576)
   if not b:break
   h.update(b)
 return {'path':str(p),'bytes':p.stat().st_size,'sha256':h.hexdigest()}
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(c):
  c.root=Path(tempfile.mkdtemp(prefix='coordinator-controls-'));os.chmod(c.root,0o700);c.m=d.modules();c.pins={}
  def file(n,b):
   p=c.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);return digest(p)
  c.file=staticmethod(file)
  inputs={k:file(k,b'public-'+k.encode()) for k in d.PUBLIC}
  c.real_pin=d.pin
  for k,n in [('scratch_template_path',1073741824),('result_template_path',268435456)]:
   p=Path(inputs[k]['path'])
   with open(p,'wb') as f:f.truncate(n)
   inputs[k]=digest(p)
  embedded={k:file(k,b'component-'+k.encode()) for k in ('kernel','initrd','system_disk')}
  manifest={'arch':'aarch64','image_id':'e'*64,'resource_profiles':{'mini-4096':{'mem_mib':4096,'vcpus':1}},**embedded}
  inputs['image_manifest_path']=file('image_manifest_path',json.dumps(manifest).encode())
  policy={'admitted_images':[{'image_id':'e'*64,'manifest_sha256':inputs['image_manifest_path']['sha256']}],'resource_limits':{'max_mem_mib':4096,'max_vcpus':1,'max_runtime_seconds':600}}
  inputs['policy_path']=file('policy_path',json.dumps(policy).encode())
  app=c.root/'Runner.app';info=file('Runner.app/Contents/Info.plist',plistlib.dumps({'CFBundleExecutable':'dsmack-runner','CFBundleIdentifier':'dev.dsmack.provider'}));exe=file('Runner.app/Contents/MacOS/dsmack-runner',b'synthetic-arm64')
  reviews={r:file('TEST-ONLY-'+r+'-review.json',json.dumps({k:True}).encode()) for r,k in d.GATE_KEYS.items()}

  closure=file('closure.json',c.m['session_parser'].canonical_bytes({'schema':'dsmack-result-closure-context/1','attempt_id':'a'*32,'selectors':['claude-coding-task-subscription-dstack']}))
  e={'enrollment_class':'apple-appattest-production','app_id':'DC9JH5DRMY.dev.dsmack.provider','team_id':'DC9JH5DRMY','environment':'production','receipt_environment':'vm','workload_status':'completed','exit_code':0,'receipt_selector':'claude-coding-task-subscription-dstack','manifest_sha256':inputs['compose_manifest_path']['sha256'],'challenge':bytes(32).hex(),'key_id_b64':base64.b64encode(bytes(32)).decode(),'closure_context':json.loads(Path(closure['path']).read_bytes())};e['selector_manifests']={e['receipt_selector']:{k:e[k] for k in ('manifest_sha256','workload_status','exit_code','receipt_environment')}}
  checker=file('checker.json',json.dumps({'schema':'dsmack.runresult-checker-context/3','verifier_id':'dsmack-runresult-verifier','verifier_version':'2','report_verify_key_b64':base64.b64encode(bytes(32)).decode(),'report_key_id':'synthetic-report-key','core_sha256':'13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5','extractor_tool_sha256':'d'*64,'expected':e}).encode())
  private=c.root/'private-vde';private.write_bytes(b'SYNTHETIC');private.chmod(0o600)
  c.p={'schema':'dsmack-protected-local-coordinator/1','status':'ready','reviews':reviews,'app':{'bundle_path':str(app),'info':info,'executable':exe,'full_cdhash':'b'*64,'team_id':'DC9JH5DRMY','bundle_id':'dev.dsmack.provider'},'inputs':inputs,'embedded':embedded,'closure_context':closure,'checker_context':checker,'spec':{**{k:v['path'] for k,v in inputs.items()},'profile':'mini-4096','workload_id':'claude-coding-task-subscription-dstack','runtime_seconds':600,'private_input_path':str(private),'net_socket_path':str(c.root/'attempt.helper/net.sock')},'helper':{'launcher':file('helper',b'synthetic-launcher'),'gvproxy':file('gvproxy',b'synthetic-gvproxy'),'run_dir':str(c.root/'attempt.helper')},'out_parent':str(c.root),'out_name':'attempt','challenge':file('challenge',bytes(32)),'key_id':file('keyid',base64.b64encode(bytes(32)))}
  # Controlled original-review/compile/signing/final-handoff fixture records.
  # All exist ONLY under this temp test tree and do not claim genuine review.
  unsigned=file('unsigned',b'synthetic-unsigned');source=file('source-manifest',b'synthetic-source');native=file('native-archive',b'synthetic-native')
  appgate={d.GATE_KEYS['app']:True,'exact_candidate_pins':{'unsigned_executable':unsigned['sha256'],'unsigned_executable_bytes':unsigned['bytes'],'info_plist':info['sha256'],'candidate_source_manifest':source['sha256'],'native_archive':native['sha256'],'native_archive_bytes':native['bytes']}}
  c.p['reviews']['app']=file('TEST-ONLY-app-review.json',json.dumps(appgate).encode())
  inv={k:hashlib.sha256(k.encode()).hexdigest() for k in ('src/lib.rs','src/main.rs','Cargo.lock','Cargo.toml')}
  helpergate={d.GATE_KEYS['helper']:True,'exact_candidate_pins':{'sha256':{'candidate/gvproxy-launcher/'+k:v for k,v in inv.items()}}};helpergate['exact_candidate_pins']['sha256']['candidate/aux/bin/native_helper.py']=c.m['native_helper'].SOURCE_SHA256
  c.p['reviews']['helper']=file('TEST-ONLY-helper-review.json',json.dumps(helpergate).encode())
  ip=file('helper-source-inventory',json.dumps(inv).encode());comp={'schema':'dsmack-repaired-helper-compile/1','actual_link_exit':0,'mini_actual_artifact':c.p['helper']['launcher'],'source_inventory':ip['path'],'source_inventory_sha256':ip['sha256']};cp=file('helper-compile',json.dumps(comp).encode())
  sign={'schema':'dsmack-local-signing-operation/1','app_review':c.p['reviews']['app'],'unsigned_executable':unsigned,'signed_executable':exe,'info_plist':info,'native_archive':native,'candidate_source_manifest':source,'full_cdhash':c.p['app']['full_cdhash']}
  sp=file('TEST-ONLY-signing-record',json.dumps(sign).encode())
  handoff={'selected_image':'e'*64,'gvproxy':c.p['helper']['gvproxy'],'runtime_public_inputs':inputs,'helper_compile_handoff':cp,'unsigned_binary_sha256':unsigned['sha256'],'native_archive_sha256':native['sha256'],'coordinator_source':digest(Path(d.__file__).resolve())}
  fp=file('TEST-ONLY-final-handoff',json.dumps(handoff).encode())
  c.p['reviews']['final']=file('TEST-ONLY-final-review.json',json.dumps({d.GATE_KEYS['final']:True,'exact_candidate_pins':{'selected_handoff_sha256':fp['sha256']}}).encode())
  c.p['bindings']={'signing_record':sp,'unsigned_executable':unsigned,'candidate_source_manifest':source,'native_archive':native,'helper_compile':cp,'helper_inventory':ip,'final_handoff':fp}


 def test_shared_failed_checker_requires_explicit_selected_outcome(self):
  p=copy.deepcopy(self.p);checker=json.loads(Path(p['checker_context']['path']).read_bytes());e=checker['expected'];e.update(workload_status='failed',exit_code=1);e['selector_manifests'][e['receipt_selector']].update(workload_status='failed',exit_code=1);p['checker_context']=self.file('failed-checker-control.json',json.dumps(checker).encode());final={'selected_image':'e'*64};verifier=lambda *args:'synthetic OS metadata'
  with self.assertRaisesRegex(ValueError,'expected workload_status'):d._validate_runtime(p,self.m,'run',final,app_verifier=verifier)
  with self.assertRaisesRegex(ValueError,'expected workload_status'):self.check(p)
  result=d._validate_runtime(p,self.m,'run',final,app_verifier=verifier,expected_outcome=('failed',1));self.assertEqual(result[0],Path(p['out_parent'])/p['out_name'])
  with self.assertRaisesRegex(ValueError,'expected workload_status'):d._validate_runtime(self.p,self.m,'run',final,app_verifier=verifier,expected_outcome=('failed',1))
 @classmethod
 def tearDownClass(c):d.pin=c.real_pin;shutil.rmtree(c.root)
 def tools(self,argv):
  if argv[0]=='/usr/bin/lipo':return b'arm64\n',b''
  if '--entitlements' in argv:
   return plistlib.dumps({'com.apple.application-identifier':'DC9JH5DRMY.dev.dsmack.provider','com.apple.developer.team-identifier':'DC9JH5DRMY','com.apple.developer.devicecheck.app-attest-opt-in':['CDhash'],'keychain-access-groups':['DC9JH5DRMY.dev.dsmack.provider'],'com.apple.security.hypervisor':True}),b''
  if '--verbose=4' in argv:return b'',('CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=20+7 location=embedded\nIdentifier=dev.dsmack.provider\nTeamIdentifier=DC9JH5DRMY\nAuthority=Apple Development: Test\nCandidateCDHashFull sha256='+'b'*64+'\n').encode()
  return b'',b''
 def check(self,p):return d.validate(p,self.m,'run',self.tools)
 def test_valid_real_format_and_twenty_field_session(self):
  _,raw,_=self.check(copy.deepcopy(self.p));self.assertEqual(len(json.loads(raw)),20)
 def test_missing_negative_and_boolean_gate(self):
  for val in (False,1,None):
   p=copy.deepcopy(self.p);p['reviews']['app']=self.file('TEST-ONLY-negative.json',json.dumps({d.GATE_KEYS['app']:val}).encode())
   with self.assertRaises(d.Refused):self.check(p)
  p=copy.deepcopy(self.p);del p['reviews']['helper']
  with self.assertRaises(d.Refused):self.check(p)
 def test_changed_public_bytes(self):
  p=copy.deepcopy(self.p);p['inputs']['metadata_path']['sha256']='0'*64
  with self.assertRaises(d.Refused):self.check(p)
 def test_cdhash_mismatch(self):
  p=copy.deepcopy(self.p);p['app']['full_cdhash']='c'*64
  with self.assertRaises(d.Refused):self.check(p)
 def test_real_cdhash_line_required(self):
  def bad(a):
   x,y=self.tools(a);return x,y.replace(b'CandidateCDHashFull sha256=',b'CandidateCDHashFull=')
  with self.assertRaises(ValueError):d.verify_app(self.p['app'],self.m['signing_policy'],bad)
 def test_wrong_profile_template_context(self):
  for key,val in [('profile','other'),('runtime_seconds',601)]:
   p=copy.deepcopy(self.p);p['spec'][key]=val
   with self.assertRaises(d.Refused):self.check(p)
  p=copy.deepcopy(self.p);p['inputs']['result_template_path']['bytes']=512
  with self.assertRaises(d.Refused):self.check(p)
  p=copy.deepcopy(self.p);p['checker_context']=self.file('bad-checker.json',b'{}')
  with self.assertRaises(d.Refused):self.check(p)
 def test_collision(self):
  p=copy.deepcopy(self.p);p['out_name']='challenge'
  with self.assertRaises(d.Refused):self.check(p)
 def test_private_mode_and_challenge(self):
  p=copy.deepcopy(self.p);p['challenge']=self.file('short-challenge',b'x')
  with self.assertRaises(d.Refused):self.check(p)
  private=Path(self.p['spec']['private_input_path']);private.chmod(0o644)
  try:
   with self.assertRaises(d.Refused):self.check(copy.deepcopy(self.p))
  finally:private.chmod(0o600)
 def test_helper_failure_retains_partial_observation(self):
  p=copy.deepcopy(self.p);p['out_name']='stop-fault';p['helper']['run_dir']=str(self.root/'stop-fault.helper');p['spec']['net_socket_path']=str(self.root/'stop-fault.helper/net.sock');v=self.check(p)
  class H:
   def __init__(s,*a):pass
   def start(s):pass
   def stop(s):return {'quiescence':'unconfirmed','cleanup_errors':['synthetic fault']}
  def launch(a,timeout):
   out=v[0];out.mkdir()
   for n in d.RUN_FILES:(out/n).write_bytes(b'fixture')
   return subprocess.CompletedProcess(a,0)
  with self.assertRaises(d.Refused):d.execute(p,self.m,'run',v,tool=launch,helper_class=H)
  report=json.loads((self.root/'stop-fault.logs/launch-observation.json').read_bytes());self.assertTrue(report['output_complete']);self.assertTrue(report['errors']);self.assertIsNone(report['evidence_valid']);self.assertTrue(v[0].exists())
 def test_enroll_prechosen_clientdata_binding(self):
  for good in (False,True):
   p=copy.deepcopy(self.p);p['out_name']='enroll-'+str(good);p['helper']['run_dir']=str(self.root/(p['out_name']+'.helper'));p['spec']['net_socket_path']=str(Path(p['helper']['run_dir'])/'net.sock');v=d.validate(p,self.m,'enroll',self.tools)
   def launch(a,timeout):
    out=v[0];out.mkdir();(out/'keyId.txt').write_bytes(b'generated-key');(out/'attestation.cbor').write_bytes(b'SYNTHETIC')
    raw=self.m['session_parser'].canonical_bytes({'domain':'minimal-attested-run-enroll/1','challenge':bytes(32).hex()}) if good else b'wrong-challenge'
    (out/'clientData.bin').write_bytes(raw);return subprocess.CompletedProcess(a,0)
   if good:self.assertTrue(d.execute(p,self.m,'enroll',v,tool=launch)['output_complete'])
   else:
    with self.assertRaises(d.Refused):d.execute(p,self.m,'enroll',v,tool=launch)
 def test_checker_independent_challenge_keyid(self):
  for expected in ({'challenge':'f'*64,'key_id_b64':base64.b64encode(bytes(32)).decode()},{'challenge':bytes(32).hex(),'key_id_b64':'other'}):
   p=copy.deepcopy(self.p);p['checker_context']=self.file('bad-expectation.json',json.dumps({**json.loads(Path(self.p['checker_context']['path']).read_bytes()),'expected':{**json.loads(Path(self.p['checker_context']['path']).read_bytes())['expected'],**expected}}).encode())
   with self.assertRaises(d.Refused):self.check(p)
 def test_full_checker_schema_field_mutations(self):
  valid=json.loads(Path(self.p['checker_context']['path']).read_bytes());d.checker_schema(valid)
  cases=[]
  for k,v in [('verifier_id','test'),('verifier_version',''),('verifier_version','v'*17),('report_key_id',''),('report_verify_key_b64','test'),('report_verify_key_b64',base64.b64encode(bytes(31)).decode()),('core_sha256','test'),('extractor_tool_sha256','test')]:
   x=copy.deepcopy(valid);x[k]=v;cases.append(x)
  for k,v in [('key_id_b64','test-key'),('key_id_b64',base64.b64encode(bytes(31)).decode()),('challenge',''),('exit_code',False),('manifest_sha256','test'),('extra',True)]:
   x=copy.deepcopy(valid);x['expected'][k]=v;cases.append(x)
  x=copy.deepcopy(valid);x['expected']['selector_manifests']['claude-coding-task-subscription-dstack']['extra']=True;cases.append(x)
  x=copy.deepcopy(valid);x['expected']['closure_context']['selectors']=['z','a'];cases.append(x)
  for x in cases:
   with self.assertRaises(d.Refused):d.checker_schema(x)
 def test_original_review_artifact_relationships(self):
  for role in ('app','helper','final'):
   p=copy.deepcopy(self.p);g=json.loads(Path(p['reviews'][role]['path']).read_bytes())
   if role=='app':g['exact_candidate_pins']['unsigned_executable']='a'*64
   elif role=='helper':g['exact_candidate_pins']['sha256']['candidate/gvproxy-launcher/src/lib.rs']='a'*64
   else:g['exact_candidate_pins']['selected_handoff_sha256']='a'*64
   p['reviews'][role]=self.file('TEST-ONLY-unrelated-'+role,json.dumps(g).encode())
   with self.assertRaises(d.Refused):self.check(p)
  p=copy.deepcopy(self.p);p['bindings']['signing_record']=self.file('TEST-ONLY-missing-signing',b'{}')
  with self.assertRaises(d.Refused):self.check(p)
  p=copy.deepcopy(self.p);comp=json.loads(Path(p['bindings']['helper_compile']['path']).read_bytes());comp['mini_actual_artifact']['sha256']='a'*64;p['bindings']['helper_compile']=self.file('TEST-ONLY-wrong-compiled',json.dumps(comp).encode())
  with self.assertRaises(d.Refused):self.check(p)
 def test_different_valid_gvproxy_refused_by_original_final_pairing(self):
  p=copy.deepcopy(self.p);p['helper']['gvproxy']=self.file('other-valid-gvproxy',b'OTHER synthetic executable')
  # Real valid bytes/length/digest now match local policy, but the ORIGINAL
  # independently selected final handoff still binds the prior gvproxy pairing.
  d.pin(p['helper']['gvproxy'])
  with self.assertRaisesRegex(d.Refused,'gvproxy pairing'):self.check(p)
 def test_stale_selected_base_and_manifest_refused(self):
  def fixture_rebind(p):
   final=json.loads(Path(p['bindings']['final_handoff']['path']).read_bytes());final['runtime_public_inputs']=p['inputs'];p['bindings']['final_handoff']=self.file('TEST-ONLY-rebound-final',json.dumps(final).encode());gate={d.GATE_KEYS['final']:True,'exact_candidate_pins':{'selected_handoff_sha256':p['bindings']['final_handoff']['sha256']}};p['reviews']['final']=self.file('TEST-ONLY-rebound-review',json.dumps(gate).encode())
  p=copy.deepcopy(self.p);manifest=json.loads(Path(p['inputs']['image_manifest_path']['path']).read_bytes());manifest['image_id']='a'*64
  # Even with a fixture review pinning these changed public inputs, a stale
  # manifest imageID cannot override the independently selected imageID.
  p['inputs']['image_manifest_path']=self.file('stale-image-manifest',json.dumps(manifest).encode());p['spec']['image_manifest_path']=p['inputs']['image_manifest_path']['path'];fixture_rebind(p)
  with self.assertRaisesRegex(d.Refused,'selected ARM64 image'):self.check(p)
  p=copy.deepcopy(self.p);p['inputs']['compose_manifest_path']=self.file('stale-compose',b'stale-compose');p['spec']['compose_manifest_path']=p['inputs']['compose_manifest_path']['path'];fixture_rebind(p)
  with self.assertRaisesRegex(d.Refused,'expected manifest_sha256'):self.check(p)
if __name__=='__main__':unittest.main(verbosity=2)
