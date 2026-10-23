"""Unit detecting controls; fake OS tools here do not qualify a Mac/VM."""
import hashlib,importlib.util,json,os,plistlib,py_compile,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
import alpha_coordinator as a

def digest(b):return hashlib.sha256(b).hexdigest()
def desc(p):b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':digest(b)}
class Alpha(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory(prefix='.at-',dir=Path.home());self.root=Path(self.t.name)
 def tearDown(self):self.t.cleanup()
 def coordinator(self):
  p=Path(__file__).parent/'coordinator/coordinator.py';return a.source_module(p,digest(p.read_bytes()))
 def test_only_closed_authenticated_baseline_profiles_select_failed_one(self):
  for i in (1,2,3):
   p={'schema':'dsmack-alpha-profile/2','profile_id':'bounty-board-search-browser-review-v1-baseline'+str(i),'execution_profile':{'profile_id':'bounty-board-search-browser-review-v1','workload_id':'bounty-board-search-browser-review-v1'}}
   self.assertEqual(a.selected_checker_outcome({'profile':p}),('failed',1))
   for k,v in [('schema','dsmack-alpha-profile/3'),('execution_profile',{'profile_id':'bounty-board-search-generate-v1','workload_id':'bounty-board-search-generate-v1'})]:
    bad=dict(p);bad[k]=v
    with self.assertRaises(ValueError):a.selected_checker_outcome({'profile':bad})
  for alias in ['bounty-board-search-browser-review-v1','bounty-board-search-browser-review-v1-suite1','bounty-board-search-primary-review-v1-primary','bounty-board-search-generate-v1-judge1','bounty-board-search-develop-v1','bounty-board-search-browser-review-v1-baseline0','bounty-board-search-browser-review-v1-baseline4','bounty-board-search-browser-review-v1-BASELINE1','bounty-board-search-browser-review-v1-baseline1-extra']:
   self.assertEqual(a.selected_checker_outcome({'profile':{'profile_id':alias,'execution_profile':{}}}),('completed',0))
 def test_unsigned_or_missing_authenticated_profile_refuses_before_selection(self):
  from unittest.mock import patch
  bootstrap=self.root/'bootstrap.json';bootstrap.write_bytes(a.canonical({'schema':'dsmack-alpha-bootstrap/2','runtime':{'node_platform':'darwin','node_arch':'arm64'}}));inventory=self.root/'inventory.json';inventory.write_bytes(b'{}');signature=self.root/'signature';signature.write_bytes(b'SYNTHETIC-NOT-A-SIGNATURE');auth={'bootstrap':desc(bootstrap),'inventory':desc(inventory),'signature':desc(signature)}
  def unsigned(*args,**kwargs):raise ValueError('signature refused')
  for authenticate in [unsigned,lambda *args,**kwargs:{'inventory':{'schema':'dsmack-alpha-release/2'},'profile':None}]:
   with patch.object(a,'installer',return_value={'authenticate':authenticate}):
    with self.assertRaises(ValueError):a.release(auth,str(self.root),'bounty-board-search-browser-review-v1-baseline1')
 def test_shared_outcome_default_stays_completed_zero_and_closed(self):
  import inspect
  c=self.coordinator();f=c['_validate_runtime'];self.assertEqual(inspect.signature(f).parameters['expected_outcome'].default,('completed',0))
  self.assertEqual(c['checker_outcome'](('completed',0)),{'workload_status':'completed','exit_code':0});self.assertEqual(c['checker_outcome'](('failed',1)),{'workload_status':'failed','exit_code':1})
  for x in [('failed',0),('completed',1),('failed',True),['failed',1],('cancelled',1),{'workload_status':'failed','exit_code':1}]:
   with self.assertRaises(ValueError):c['checker_outcome'](x)
 def test_both_alpha_validation_paths_use_authenticated_profile_not_checker(self):
  import ast
  tree=ast.parse((Path(__file__).parent/'alpha_coordinator.py').read_bytes());calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Subscript)and isinstance(n.func.slice,ast.Constant)and n.func.slice.value=='_validate_runtime'];self.assertEqual(len(calls),2)
  for call in calls:
   kw=next(k for k in call.keywords if k.arg=='expected_outcome');self.assertIsInstance(kw.value,ast.Call);self.assertEqual(kw.value.func.id,'selected_checker_outcome');self.assertEqual(kw.value.args[0].id,'checked')
 def test_instance_private_permission_uses_closed_canonical_selector(self):
  self.assertEqual(len(a.PROFILE_INSTANCES),10)
  for i in range(1,4):
   alias='bounty-board-search-generate-v1-judge'+str(i)
   self.assertEqual(a.canonical_profile(alias),'bounty-board-search-generate-v1')
   p=self.root/('private'+str(i));p.write_bytes(b'private');os.chmod(p,0o600)
   profile={'schema':'dsmack-alpha-profile/3','profile_id':alias,'private_input_policy':{'schema':'dsmack-alpha-private-channel/1','channel':'runtime-envelope-v1','max_bytes':1073741824,'public_runtime_envelope':False},'execution_profile':{'scratch_template_bytes':4294967296}}
   self.assertEqual(a.private_input({'private_input_path':str(p)},profile),str(p))
   profile['profile_id']=alias+'-unknown'
   with self.assertRaises(ValueError):a.private_input({'private_input_path':str(p)},profile)
  self.assertEqual(a.canonical_profile('bounty-board-search-browser-review-v1-suite1'),'bounty-board-search-browser-review-v1')
  self.assertEqual(a.canonical_profile('bounty-board-search-primary-review-v1-primary'),'bounty-board-search-primary-review-v1')
 def test_selected_installer_ignores_matching_header_bytecode_cache(self):
  for name in ('alpha_coordinator.py','alpha_stage.py'):shutil.copyfile(Path(__file__).parent/name,self.root/name)
  target=self.root/'alpha_stage.py';original=target.read_bytes();st=target.stat();marker=self.root/'CACHE';bad=("from pathlib import Path;Path("+repr(str(marker))+").touch()\n").encode();bad+=b' '*(len(original)-len(bad));target.write_bytes(bad);os.utime(target,ns=(st.st_atime_ns,st.st_mtime_ns));py_compile.compile(str(target),doraise=True);target.write_bytes(original);os.utime(target,ns=(st.st_atime_ns,st.st_mtime_ns))
  sp=importlib.util.spec_from_file_location('old_cache_control',target);mod=importlib.util.module_from_spec(sp);sp.loader.exec_module(mod);self.assertTrue(marker.exists());marker.unlink()
  ns=a.source_module(self.root/'alpha_coordinator.py',digest((self.root/'alpha_coordinator.py').read_bytes()));self.assertIn('authenticate',ns['installer']());self.assertFalse(marker.exists())
 def test_old_engineering_approval_object_is_not_an_alpha_plan(self):
  plan=self.root/'plan.json';plan.write_text(json.dumps({'schema':'dsmack-protected-local-coordinator/1','approved_for_signing_and_live_qualification':True}));os.chmod(plan,0o600)
  p=subprocess.run([sys.executable,'-I',str(Path(__file__).parent/'alpha_coordinator.py'),'--execute','--plan',str(plan)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.assertEqual(p.returncode,2);self.assertIn(b'plan schema',p.stderr);self.assertEqual(list(self.root.iterdir()),[plan])
 def test_task_cannot_supply_profile_override_or_approval(self):
  c=self.coordinator();path=self.root/'task.json';path.write_text(json.dumps({'schema':'dsmack-alpha-local-task/1','profile_id':'other','approved':True}));os.chmod(path,0o600)
  with self.assertRaises(ValueError):a.task_inputs(path,c,'bounty-board-search-browser-review-v1')
 def test_authenticated_other_attempt_refuses_before_disk_access(self):
  from unittest.mock import patch
  profile={'schema':'dsmack-alpha-profile/2','profile_id':'bounty-board-search-browser-review-v1'};checked={'profile':profile,'inventory_sha256':'a'*64}
  boot=self.root/'bootstrap.json';boot.write_text('{}');ctx=self.root/'context.json';ctx.write_bytes(a.canonical({'attempt_id':'b'*32}))
  task={'schema':'dsmack-alpha-local-task/2','workload_admission':{'path':'public-admission'},'workload_signature':{'path':'public-signature'},'workload_disk':{'path':'must-not-open','bytes':1,'sha256':'c'*64},'closure_context':{'path':str(ctx)}}
  claim={'attempt_id':'d'*32,'closure_context_sha256':digest(ctx.read_bytes()),'workload_disk':{'bytes':1,'sha256':'c'*64}}
  admitted=dict(checked,workload=claim)
  with patch.object(a,'installer',return_value={'authenticate':lambda *args,**kwargs:admitted}):
   with self.assertRaisesRegex(ValueError,'admission closure differs'):a.validate_workload({'bootstrap':{'path':str(boot)},'inventory':{'path':'inventory'},'signature':{'path':'signature'}},str(self.root),checked,task,{'document':lambda d:json.loads(Path(d['path']).read_bytes())})
 def test_shared_engineering_gate_still_refuses_before_runtime(self):
  c=self.coordinator()
  with self.assertRaises(ValueError):c['validate']({'approved_for_signing_and_live_qualification':True},{},'run')
  with self.assertRaises((ValueError,KeyError)):c['execute']({'reviews':{}},{},'run',None)
 def test_derivation_uses_exact_signed_roles_without_review_objects(self):
  c=self.coordinator();attempt='a'*32;closure=self.root/'closure.json';closure.write_bytes(a.canonical({'schema':'dsmack-result-closure-context/1','attempt_id':attempt,'selectors':['bounty-board-search-browser-review-v1']}));control=self.root/'control';control.mkdir(mode=0o700)
  roles={k:'assets/'+k for k in ['kernel','initrd','system_disk','app_executable','app_info','checksum_manifest','metadata','base_admission','compose_manifest','workload_disk','scratch_template','result_template','helper_launcher','helper_gvproxy']};files=[{'path':v,'bytes':1,'sha256':'b'*64,'mode':0o600} for v in roles.values()]
  q={'schema':'dsmack-protected-execution-profile/1','profile_id':'bounty-board-search-browser-review-v1','workload_id':'bounty-board-search-browser-review-v1','resource_profile':'mini-4096','memory_mib':4096,'vcpus':1,'runtime_seconds':600,'scratch_template_bytes':4294967296,'result_template_bytes':268435456,'compose_manifest_sha256':'b'*64,'model_profile':'none','security_preset':'browser-sandbox-v1'}
  checked={'inventory_sha256':'c'*64,'inventory':{'files':files,'app':{'team_id':'DC9JH5DRMY','bundle_id':'dev.dsmack.provider','cdhash_full':'d'*64}},'profile':{'schema':'dsmack-alpha-profile/2','roles':roles,'app_bundle':'Runner.app','profile_id':q['profile_id'],'execution_profile':q,'selected_image':'e'*64,'image':{'root_hash':'f'*64,'kernel_cmdline':'console=hvc0','rootfs_size':1}}}
  task={'workload_disk':desc(closure),'closure_context':desc(closure),'checker_context':desc(closure),'challenge':desc(closure),'key_id':desc(closure)}
  p,final=a.derive(self.root,checked,task,self.root,control,c,write_files=True);self.assertNotIn('reviews',p);self.assertNotIn('bindings',p);self.assertEqual(final['execution_profile'],q);self.assertEqual(p['spec']['private_input_path'],'');self.assertEqual(set(p['inputs']),set(c['PUBLIC']))
  image=json.loads((control/'image-manifest.json').read_bytes());self.assertEqual(image['kernel']['path'],str(self.root/roles['kernel']));self.assertEqual(image['image_id'],'e'*64)
  (control/'policy.json').write_text('{}')
  with self.assertRaisesRegex(ValueError,'derived local policy'):a.derive(self.root,checked,task,self.root,control,c)
 def test_real_os_policy_boundary_uses_all_checks_and_refuses_wrong_leaf(self):
  c=self.coordinator();sp=c['modules']()['signing_policy'];policy_path=Path(__file__).parent/'alpha_signing_policy.py';alpha=a.source_module(policy_path,digest(policy_path.read_bytes()))
  bundle=self.root/'Runner.app';(bundle/'Contents/MacOS').mkdir(parents=True,mode=0o700);info=bundle/'Contents/Info.plist';info.write_bytes(plistlib.dumps({'CFBundleIdentifier':'dev.dsmack.provider','CFBundleExecutable':'runner'}));exe=bundle/'Contents/MacOS/runner';exe.write_bytes(b'unit fixture')
  roles={'app_info':'Runner.app/Contents/Info.plist','app_executable':'Runner.app/Contents/MacOS/runner','notary_evidence':'notary.json'};identity={'team_id':'DC9JH5DRMY','bundle_id':'dev.dsmack.provider','cdhash_full':'a'*64,'certificate_sha256':digest(b'public test leaf')}
  ents=plistlib.dumps({'com.apple.application-identifier':'DC9JH5DRMY.dev.dsmack.provider','com.apple.developer.team-identifier':'DC9JH5DRMY','com.apple.developer.devicecheck.app-attest-opt-in':['CDhash'],'keychain-access-groups':['DC9JH5DRMY.dev.dsmack.provider'],'com.apple.security.hypervisor':True});identity['entitlements_sha256']=digest(ents)
  record={'schema':'dsmack-alpha-notarization/1','app':{k:identity[k] for k in ('team_id','bundle_id','cdhash_full','certificate_sha256')},'checks':{'codesign':True,'stapler':True,'distribution_assessment':True},'submission':{'status':'notarized-ticket-validated','observed_job_status':'processing'}};(self.root/'notary.json').write_text(json.dumps(record))
  files=[dict(desc(self.root/path),path=path,mode=0o600) for path in roles.values()];checked={'inventory':{'app':identity,'files':files},'profile':{'app_bundle':'Runner.app','roles':roles}};app={'bundle_path':str(bundle),'info':desc(info),'executable':desc(exe)};calls=[]
  metadata='\n'.join(['Identifier=dev.dsmack.provider','TeamIdentifier=DC9JH5DRMY','Authority='+alpha['AUTHORITY'],'CodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=1+0 location=embedded','CandidateCDHashFull sha256='+'a'*64,'Timestamp=Oct22'])
  def tool(argv):
   calls.append(argv)
   if argv[0]=='/usr/bin/lipo':return b'arm64',b''
   if '--verbose=4' in argv:return b'',metadata.encode()
   if '--entitlements' in argv:return ents,b''
   for arg in argv:
    if arg.startswith('--extract-certificates='):Path(arg.split('=',1)[1]+'0').write_bytes(b'public test leaf')
   if argv[0]=='/usr/bin/syspolicy_check':return b'{"output":[]}',b''
   return b'',b''
  self.assertEqual(a.verify_app(app,sp,tool,root=self.root,checked=checked,alpha=alpha),metadata)
  self.assertTrue(any(x[0]=='/usr/bin/xcrun' for x in calls));self.assertTrue(any(x[0]=='/usr/bin/syspolicy_check' for x in calls));identity['certificate_sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'leaf'):a.verify_app(app,sp,tool,root=self.root,checked=checked,alpha=alpha)
 def test_private_profile_metadata_only_and_caps(self):
  from unittest.mock import patch
  path=self.root/'private-envelope';path.write_bytes(b'synthetic-not-a-real-credential');path.chmod(0o600)
  profile={'schema':'dsmack-alpha-profile/3','profile_id':'bounty-board-search-develop-v1','private_input_policy':{'schema':'dsmack-alpha-private-channel/1','channel':'runtime-envelope-v1','max_bytes':1<<30,'public_runtime_envelope':False},'execution_profile':{'scratch_template_bytes':4<<30}}
  task={'private_input_path':str(path)}
  with patch.object(a.os,'read',side_effect=AssertionError('Private content must not be read')):self.assertEqual(a.private_input(task,profile),str(path))
  for mode in (0o644,0o400,0o660):
   path.chmod(mode)
   with self.assertRaises(ValueError):a.private_input(task,profile)
  path.chmod(0o600);link=self.root/'link';link.symlink_to(path)
  with self.assertRaises(ValueError):a.private_input({'private_input_path':str(link)},profile)
  hard=self.root/'hard';os.link(path,hard)
  with self.assertRaises(ValueError):a.private_input(task,profile)
  hard.unlink()
  with path.open('r+b') as f:f.truncate((1<<30)+1)
  with self.assertRaisesRegex(ValueError,'cap'):a.private_input(task,profile)
  path.write_bytes(b'x');profile['private_input_policy']['public_runtime_envelope']=True
  with self.assertRaises(ValueError):a.private_input(task,profile)
 def test_task_versions_cross_pair_and_private_browser_refuse(self):
  c=self.coordinator();path=self.root/'task.json'
  context=self.root/'context';context.write_bytes(a.canonical({'attempt_id':'a'*32}));task={'schema':'dsmack-alpha-local-task/3','profile_id':'bounty-board-search-develop-v1','private_input_path':str(self.root/'private')}
  for k in ('closure_context','checker_context','challenge','key_id','workload_admission','workload_signature','workload_disk'):task[k]=desc(context)
  path.write_bytes(a.canonical(task));path.chmod(0o600);self.assertEqual(a.task_inputs(path,c,task['profile_id'])[1],'a'*32)
  for update in ({'schema':'dsmack-alpha-local-task/2'},{'profile_id':'bounty-board-search-browser-review-v1','schema':'dsmack-alpha-local-task/2'}):
   bad={**task,**update};path.write_bytes(a.canonical(bad))
   with self.assertRaises(ValueError):a.task_inputs(path,c,bad['profile_id'])
 def test_generate_task3_explicit_private_path(self):
  c=self.coordinator();path=self.root/'task';context=self.root/'context';context.write_bytes(a.canonical({'attempt_id':'a'*32}));task={'schema':'dsmack-alpha-local-task/3','profile_id':'bounty-board-search-generate-v1','private_input_path':str(self.root/'private')}
  for k in ('closure_context','checker_context','challenge','key_id','workload_admission','workload_signature','workload_disk'):task[k]=desc(context)
  path.write_bytes(a.canonical(task));path.chmod(0o600);self.assertEqual(a.task_inputs(path,c,task['profile_id'])[1],'a'*32)
  for bad in ({**task,'schema':'dsmack-alpha-local-task/2'},{k:v for k,v in task.items() if k!='private_input_path'}):
   path.write_bytes(a.canonical(bad))
   with self.assertRaises(ValueError):a.task_inputs(path,c,task['profile_id'])
if __name__=='__main__':unittest.main()
