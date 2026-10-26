"""Signed-release alpha entry. Engineering review files are not input authority.

The installer must authenticate this source before initial invocation. Each launch
reauthenticates the external root/expiry/floor and complete installed closure.
"""
import argparse,datetime,hashlib,json,os,platform,plistlib,re,stat,sys,tempfile
from pathlib import Path

def need(ok,msg):
 if not ok:raise ValueError(msg)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def read(path,cap=1048576,private=False):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=cap,'regular bounded file')
  if private:need(s.st_uid==os.getuid() and not s.st_mode&0o077,'private owned record')
  b=b''
  while len(b)<=cap:
   c=os.read(fd,min(1048576,cap+1-len(b)))
   if not c:break
   b+=c
  need(len(b)<=cap,'file cap');return b
 finally:os.close(fd)
def small_pin(path):
 b=read(path);return {'path':str(Path(path).resolve()),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def protected(path,private=False):
 p=Path(path);need(p.is_absolute(),'absolute protected path')
 for x in (p,*p.parents):
  s=os.lstat(x);need(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'protected path ancestry')
 if private:need(os.lstat(p).st_uid==os.getuid() and not os.lstat(p).st_mode&0o077,'private output parent')
def module(b,path):
 ns={'__name__':'dsmack_alpha_selected','__file__':str(path),'SOURCE_SHA256':hashlib.sha256(b).hexdigest()};exec(compile(b,str(path),'exec'),ns);return ns
def source_module(path,expected):
 b=read(path,262144);need(hashlib.sha256(b).hexdigest()==expected,'source module pin');return module(b,path)

def installer():
 path=Path(__file__).with_name('alpha_stage.py');return module(read(path,262144),path)

def release(auth,root,profile_id):
 helper=installer();bp=Path(auth['bootstrap']['path']);protected(bp)
 for row in auth.values():
  b=read(row['path']);need(len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256'],'launch input pin changed')
 bootstrap=json.loads(read(bp,65536));need(bootstrap.get('schema')=='dsmack-alpha-bootstrap/2' and bootstrap.get('runtime',{}).get('node_platform')=='darwin' and bootstrap.get('runtime',{}).get('node_arch')=='arm64','qualified Darwin ARM64 bootstrap/2 required');checked=helper['authenticate'](bootstrap,auth['inventory']['path'],auth['signature']['path'],root=root,profile=profile_id)
 v=checked['inventory'];p=checked['profile'];need(v['schema']=='dsmack-alpha-release/2' and p is not None,'actual alpha profile')
 statepath=Path(root).parent/'alpha-release-state.json';protected(statepath);state=json.loads(read(statepath,65536,True))
 need(set(state)=={'schema','key_id','channel','root_sha256','minimum_sequence','inventory_sha256'} and state['schema']=='dsmack-alpha-release-state/1','persisted state')
 need(state['key_id']==bootstrap['key_id'] and state['channel']==bootstrap['channel'] and state['root_sha256']==bootstrap['trust_key']['sha256'],'release authority state')
 need(type(state['minimum_sequence']) is int and v['sequence']>=state['minimum_sequence'],'launch rollback refused')
 if v['sequence']==state['minimum_sequence']:need(checked['inventory_sha256']==state['inventory_sha256'],'launch equivocation refused')
 files={f['path']:f for f in v['files']}
 for role in ('app_executable','helper_launcher','helper_gvproxy'):need(files[p['roles'][role]]['mode']==0o700,'executable role mode')
 for role,name in [('alpha_verifier','alpha-release-cli.mjs'),('alpha_library','alpha-release.mjs'),('alpha_profile','alpha-profile.mjs')]:
  f=files[p['roles'][role]];b=bootstrap['sources'][name];need((f['bytes'],f['sha256'])==(b['bytes'],b['sha256']),'bootstrap/release verifier source drift')
 need((Path(root)/p['roles']['alpha_entry']).resolve()==Path(__file__).resolve(),'selected alpha entry path')
 need(files[p['roles']['installer']]['sha256']==helper['SOURCE_SHA256'] and (Path(root)/p['roles']['installer']).resolve()==Path(__file__).with_name('alpha_stage.py').resolve(),'selected installer closure')
 need(platform.system()=='Darwin' and platform.machine()=='arm64','alpha requires Apple Silicon macOS')
 version=lambda s:tuple((list(map(int,s.split('.')))+[0,0,0])[:3])
 need(re.fullmatch(r'\d+(?:\.\d+){0,2}',v['platform']['minimum_version']) and version(platform.mac_ver()[0])>=version(v['platform']['minimum_version']),'minimum macOS version')
 return checked

def selected_modules(root,checked):
 v=checked['inventory'];p=checked['profile'];files={f['path']:f for f in v['files']};base=Path(root)
 cpath=base/p['roles']['coordinator'];c=source_module(cpath,files[p['roles']['coordinator']]['sha256'])
 m=c['modules']()
 for name in c['MODULES']:
  need(base/p['roles'][name]==cpath.parent/'modulepack'/(name+'.py') and files[p['roles'][name]]['sha256']==m[name].SOURCE_SHA256,'exact executed coordinator role')
 a=source_module(base/p['roles']['alpha_signing_policy'],files[p['roles']['alpha_signing_policy']]['sha256'])
 return c,m,a

def verify_app(a,sp,tool,*,root,checked,alpha):
 v=checked['inventory'];p=checked['profile'];identity=v['app'];bundle=Path(root)/p['app_bundle']
 need(a['bundle_path']==str(bundle),'selected app bundle path')
 for k in ('executable','info'):
  role='app_'+k;entry=next(f for f in v['files'] if f['path']==p['roles'][role]);need(a[k]=={'path':str(Path(root)/entry['path']),'bytes':entry['bytes'],'sha256':entry['sha256']},'app role pin')
 info=plistlib.loads(read(a['info']['path']));need(info.get('CFBundleIdentifier')==identity['bundle_id'] and a['executable']['path']==str(bundle/'Contents/MacOS'/info.get('CFBundleExecutable','')),'app plist/executable')
 arch,_=tool(['/usr/bin/lipo','-archs',a['executable']['path']]);need(arch.strip()==b'arm64','app architecture')
 tool(['/usr/bin/codesign','--verify','--strict','--deep',str(bundle)])
 out,err=tool(['/usr/bin/codesign','-d','--verbose=4',str(bundle)]);metadata=(out+err).decode();alpha['check_metadata'](metadata,policy_version=alpha['POLICY_VERSION'],expected_cdhash=identity['cdhash_full'])
 out,_=tool(['/usr/bin/codesign','-d','--entitlements','-','--xml',str(bundle)]);need(hashlib.sha256(out).hexdigest()==identity['entitlements_sha256'],'actual entitlement digest');sp.check_entitlements_version(out,sp.POLICY_VERSION_HVF,identity['team_id'],identity['bundle_id'])
 with tempfile.TemporaryDirectory(prefix='.alpha-public-leaf-',dir=Path(root).parent) as tmp:
  prefix=str(Path(tmp)/'cert');tool(['/usr/bin/codesign','-d','--extract-certificates='+prefix,str(bundle)]);need(hashlib.sha256(read(prefix+'0',16384)).hexdigest()==identity['certificate_sha256'],'actual leaf certificate')
 tool(['/usr/bin/xcrun','stapler','validate',str(bundle)]);out,_=tool(['/usr/bin/syspolicy_check','distribution',str(bundle),'--json']);assessment=json.loads(out);need(assessment.get('output')==[],'explicit OS distribution assessment')
 record=json.loads(read(Path(root)/p['roles']['notary_evidence']));need(record.get('schema')=='dsmack-alpha-notarization/1' and record.get('app')=={k:identity[k] for k in ('team_id','bundle_id','cdhash_full','certificate_sha256')},'notary evidence identity')
 need(record.get('checks')=={'codesign':True,'stapler':True,'distribution_assessment':True} and record.get('submission',{}).get('status')=='notarized-ticket-validated','notary evidence outcomes')
 return metadata

PROFILE_INSTANCES={'bounty-board-search-generate-v1-judge1': 'bounty-board-search-generate-v1', 'bounty-board-search-generate-v1-judge2': 'bounty-board-search-generate-v1', 'bounty-board-search-generate-v1-judge3': 'bounty-board-search-generate-v1', 'bounty-board-search-browser-review-v1-suite1': 'bounty-board-search-browser-review-v1', 'bounty-board-search-browser-review-v1-suite2': 'bounty-board-search-browser-review-v1', 'bounty-board-search-browser-review-v1-suite3': 'bounty-board-search-browser-review-v1', 'bounty-board-search-browser-review-v1-baseline1': 'bounty-board-search-browser-review-v1', 'bounty-board-search-browser-review-v1-baseline2': 'bounty-board-search-browser-review-v1', 'bounty-board-search-browser-review-v1-baseline3': 'bounty-board-search-browser-review-v1', 'bounty-board-search-primary-review-v1-primary': 'bounty-board-search-primary-review-v1'}
PRIVATE_PROFILES=('bounty-board-search-develop-v1','bounty-board-search-generate-v1','claude-broker-diagnostic-v1','agent-turns-edit-v1')
def canonical_profile(profile):
 return PROFILE_INSTANCES.get(profile,profile)

def task_inputs(path,c,profile):
 protected(path);raw=read(path,65536,True);task=c['load_bytes'](raw)
 developing=canonical_profile(profile) in PRIVATE_PROFILES
 fields={'schema','profile_id','closure_context','checker_context','challenge','key_id','workload_disk','workload_admission','workload_signature'}
 if developing:fields.add('private_input_path')
 need(set(task)==fields and task['schema']==('dsmack-alpha-local-task/3' if developing else 'dsmack-alpha-local-task/2') and task['profile_id']==profile,'task fields/profile')
 for role in ('closure_context','checker_context','challenge','key_id','workload_admission','workload_signature'):c['pin'](task[role])
 closure=c['document'](task['closure_context']);need(re.fullmatch('[a-f0-9]{32}',closure.get('attempt_id','')),'task attempt')
 return task,closure['attempt_id']

def private_input(task,profile):
 need(profile['schema']=='dsmack-alpha-profile/3' and canonical_profile(profile['profile_id']) in PRIVATE_PROFILES,'Explicit private profile required')
 policy=profile['private_input_policy'];need(policy=={'schema':'dsmack-alpha-private-channel/1','channel':'runtime-envelope-v1','max_bytes':1073741824,'public_runtime_envelope':False},'Private channel policy')
 path=task.get('private_input_path');need(isinstance(path,str) and path and '\0' not in path,'Private input path required');protected(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=min(policy['max_bytes'],profile['execution_profile']['scratch_template_bytes']),'Private input metadata/cap')
 finally:os.close(fd)
 return path

def validate_workload(auth,root,checked,task,c):
 p=checked['profile'];developing=p['schema']=='dsmack-alpha-profile/3'
 need(p['schema'] in ('dsmack-alpha-profile/2','dsmack-alpha-profile/3'),'Reusable profile required')
 need(task.get('schema')==('dsmack-alpha-local-task/3' if developing else 'dsmack-alpha-local-task/2'),'Task/profile version mismatch')
 if developing:private_input(task,p)
 bootstrap=json.loads(read(auth['bootstrap']['path'],65536))
 admitted=installer()['authenticate'](bootstrap,auth['inventory']['path'],auth['signature']['path'],root=root,profile=p['profile_id'],workload_admission=task['workload_admission']['path'],workload_signature=task['workload_signature']['path'])
 need(admitted['inventory_sha256']==checked['inventory_sha256'] and admitted['profile']==p,'Workload release changed')
 claim=admitted['workload'];need(isinstance(claim,dict),'Authenticated workload required')
 descriptor=task['workload_disk'];need(set(descriptor)=={'path','bytes','sha256'} and {k:descriptor[k] for k in ('bytes','sha256')}==claim['workload_disk'],'Workload descriptor differs from admission')
 raw=read(task['closure_context']['path'],65536);context=c['document'](task['closure_context'])
 need(context['attempt_id']==claim['attempt_id'] and hashlib.sha256(raw).hexdigest()==claim['closure_context_sha256'],'Workload admission closure differs')
 checker=c['document'](task['checker_context']);need(checker['expected']['closure_context']==context,'Checker closure differs')
 entry=next(f for f in checked['inventory']['files'] if f['path']==p['roles']['public_task'])
 scanner=source_module(Path(root)/entry['path'],entry['sha256'])
 inspected=scanner['scan_payload'](descriptor,p['execution_profile']['workload_id'],p['execution_profile']['compose_manifest_sha256'],raw)
 if developing:need(not any(name in ('public-inputs','envelopes','broker') or name.startswith(('public-inputs/','envelopes/','broker/')) for name in set(inspected['files'])|set(inspected['directories'])),'Private profile forbids competing public runtime envelope')
 return claim

def current_authorities(checked,claim):
 now=datetime.datetime.now(datetime.timezone.utc)
 for authority in (checked['inventory'],claim):
  expires=datetime.datetime.fromisoformat(authority['expires_at'].replace('Z','+00:00'));need(now<expires,'release/workload expired before launch')

BASELINE_INSTANCES=frozenset('bounty-board-search-browser-review-v1-baseline'+str(i) for i in (1,2,3))
def selected_checker_outcome(checked):
 # Only an already authenticated signed profile selects the baseline outcome.
 p=checked['profile'];q=p['execution_profile']
 if p['profile_id'] in BASELINE_INSTANCES:
  need(p['schema']=='dsmack-alpha-profile/2' and q['profile_id']=='bounty-board-search-browser-review-v1' and q['workload_id']=='bounty-board-search-browser-review-v1','closed signed baseline outcome')
  return ('failed',1)
 return ('completed',0)

def derive(root,checked,task,out_parent,control,c,*,write_files=False):
 v=checked['inventory'];profile=checked['profile'];q=profile['execution_profile'];files={f['path']:f for f in v['files']};base=Path(root)
 def role(k):
  e=files[profile['roles'][k]];return {'path':str(base/e['path']),'bytes':e['bytes'],'sha256':e['sha256']}
 closure=c['document'](task['closure_context']);name='attempt-'+closure['attempt_id'];out_parent=Path(out_parent);protected(out_parent,True)
 embedded={k:role(k) for k in ('kernel','initrd','system_disk')};system=dict(embedded['system_disk'],format='raw',verity_root_hash=profile['image']['root_hash'])
 image={'schema':'dsmack-general-launcher/image-manifest/1','arch':'aarch64','description':'Signed alpha private develop workload' if profile['schema']=='dsmack-alpha-profile/3' else 'Signed alpha credential-free browser diagnostic','image_id':profile['selected_image'],'cmdline':profile['image']['kernel_cmdline'],'guest':{'console':'hvc0','scratch_device':'vdb','workload_device':'vdc','supervisor_markers':'DSMACK_RESULT_CLOSED_V1'},'kernel':embedded['kernel'],'initrd':embedded['initrd'],'system_disk':system,'resource_profiles':{'mini-4096':{'mem_mib':4096,'vcpus':1,'basis':'Signed release browser profile:4096MiB/1vCPU'}},'provenance':{'release_inventory_sha256':checked['inventory_sha256'],'profile_id':profile['profile_id']}}
 image_raw=canonical(image);policy={'schema':'dsmack-general-launcher/admission-policy/1','policy_id':'signed-alpha-browser-4096-1-600','notes':'Signed release private development; no acceptance or payment authority' if profile['schema']=='dsmack-alpha-profile/3' else 'Signed release credential-free diagnostic; no acceptance or payment authority','admitted_images':[{'image_id':profile['selected_image'],'manifest_sha256':hashlib.sha256(image_raw).hexdigest(),'admitted_by':'authenticated-release:'+checked['inventory_sha256']}],'resource_limits':{'max_mem_mib':4096,'max_vcpus':1,'max_runtime_seconds':600},'device_contract':{'system':'vda','scratch':'vdb','workload':'vdc'}}
 for filename,raw in [('image-manifest.json',image_raw),('policy.json',canonical(policy))]:
  path=Path(control)/filename
  if write_files:c['exclusive'](path,raw)
  else:need(read(path)==raw,'derived local policy changed')
 inputs={k+'_path':role(k) for k in ('checksum_manifest','metadata','base_admission','compose_manifest','scratch_template','result_template')};inputs['workload_disk_path']=task['workload_disk'];inputs['admission_path']=inputs.pop('base_admission_path');inputs['policy_path']=small_pin(Path(control)/'policy.json');inputs['image_manifest_path']=small_pin(Path(control)/'image-manifest.json')
 spec={k:row['path'] for k,row in inputs.items()};helper_dir=out_parent/(name+'.helper');need(len(str(helper_dir/'net.sock').encode())<104,'output parent too long for Unix socket')
 spec.update(profile=q['resource_profile'],workload_id=q['workload_id'],runtime_seconds=q['runtime_seconds'],private_input_path=private_input(task,profile) if profile['schema']=='dsmack-alpha-profile/3' else '',net_socket_path=str(helper_dir/'net.sock'))
 identity=v['app'];app={'bundle_path':str(base/profile['app_bundle']),'executable':role('app_executable'),'info':role('app_info'),'full_cdhash':identity['cdhash_full'],'team_id':identity['team_id'],'bundle_id':identity['bundle_id']}
 p={'app':app,'inputs':inputs,'embedded':embedded,'spec':spec,'closure_context':task['closure_context'],'checker_context':task['checker_context'],'challenge':task['challenge'],'key_id':task['key_id'],'helper':{'launcher':role('helper_launcher'),'gvproxy':role('helper_gvproxy'),'run_dir':str(helper_dir)},'out_parent':str(out_parent),'out_name':name}
 return p,{'execution_profile':q,'selected_image':profile['selected_image']}

def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--prepare',action='store_true');g.add_argument('--check-only',action='store_true');g.add_argument('--execute',action='store_true');g.add_argument('--resume',action='store_true')
 for name in ('bootstrap','inventory','signature','root','profile','task','out-parent','plan'):ap.add_argument('--'+name)
 x=ap.parse_args()
 if x.prepare:
  need(all(getattr(x,k.replace('-','_')) for k in ('bootstrap','inventory','signature','root','profile','task','out-parent')) and not x.plan,'prepare inputs')
  auth={k:small_pin(getattr(x,k)) for k in ('bootstrap','inventory','signature')};root=os.path.abspath(x.root);checked=release(auth,root,x.profile);c,m,a=selected_modules(root,checked);task,attempt=task_inputs(Path(os.path.abspath(x.task)),c,x.profile);validate_workload(auth,root,checked,task,c);parent=Path(os.path.abspath(x.out_parent));protected(parent,True)
  control=parent/('attempt-'+attempt+'.control');need(not os.path.lexists(control),'existing attempt control; inspect saved plan/resume');control.mkdir(mode=0o700)
  p,final=derive(root,checked,task,parent,control,c,write_files=True)
  verifier=lambda app,sp,tool:verify_app(app,sp,tool,root=root,checked=checked,alpha=a)
  c['_validate_runtime'](p,m,'run',final,app_verifier=verifier,expected_outcome=selected_checker_outcome(checked))
  plan={'schema':'dsmack-alpha-launch-plan/1','admission':auth,'root':root,'profile_id':x.profile,'task':small_pin(Path(os.path.abspath(x.task))),'out_parent':str(parent),'inventory_sha256':checked['inventory_sha256'],'attempt_id':attempt}
  dest=control/'plan.json';c['exclusive'](dest,canonical(plan));syncdir(control);syncdir(parent)
  print(json.dumps({'prepared':True,'plan':str(dest),'plan_sha256':hashlib.sha256(canonical(plan)).hexdigest(),'executed':False,'evidence_valid':None}));return
 need(x.plan and not any(getattr(x,k) for k in ('bootstrap','inventory','signature','root','profile','task','out_parent')),'use protected plan only')
 planpath=Path(os.path.abspath(x.plan));protected(planpath);raw=read(planpath,65536,True);plan=json.loads(raw);need(set(plan)=={'schema','admission','root','profile_id','task','out_parent','inventory_sha256','attempt_id'} and plan['schema']=='dsmack-alpha-launch-plan/1','plan schema')
 need(isinstance(plan['attempt_id'],str) and re.fullmatch('[a-f0-9]{32}',plan['attempt_id']),'plan attempt ID')
 control=planpath.parent;need(control==Path(plan['out_parent'])/('attempt-'+plan['attempt_id']+'.control'),'plan attempt path')
 if x.resume:
  journal=control/'launch-requested.json';observation=control/'controller-result.json'
  print(json.dumps({'attempt_id':plan['attempt_id'],'launch_requested':journal.exists(),'controller_observation_available':observation.exists(),'relaunch_performed':False,'evidence_valid':None,'task_success':None}));return
 def validate_again():
  checked=release(plan['admission'],plan['root'],plan['profile_id']);need(checked['inventory_sha256']==plan['inventory_sha256'],'selected release changed');c,m,a=selected_modules(plan['root'],checked)
  t=plan['task'];b=read(t['path']);need(len(b)==t['bytes'] and hashlib.sha256(b).hexdigest()==t['sha256'],'task changed');task,attempt=task_inputs(t['path'],c,plan['profile_id']);need(attempt==plan['attempt_id'],'attempt changed');claim=validate_workload(plan['admission'],plan['root'],checked,task,c)
  p,final=derive(plan['root'],checked,task,plan['out_parent'],control,c)
  verifier=lambda app,sp,tool:verify_app(app,sp,tool,root=plan['root'],checked=checked,alpha=a)
  validated=c['_validate_runtime'](p,m,'run',final,app_verifier=verifier,expected_outcome=selected_checker_outcome(checked));current_authorities(checked,claim);return checked,c,m,p,validated
 checked,c,m,p,v=validate_again()
 if x.check_only:print(json.dumps({'checked':True,'executed':False,'inventory_sha256':checked['inventory_sha256'],'evidence_valid':None,'task_success':None}));return
 # Repeat release/expiry/floor/all source+input+OS checks immediately before writes.
 checked,c,m,p,v=validate_again();journal={'schema':'dsmack-alpha-launch-request/1','plan_sha256':hashlib.sha256(raw).hexdigest(),'inventory_sha256':checked['inventory_sha256'],'attempt_id':plan['attempt_id'],'state':'launch-requested'}
 c['exclusive'](control/'launch-requested.json',canonical(journal));syncdir(control)
 try:report=c['_execute_runtime'](p,m,'run',v)
 except BaseException as exc:
  c['exclusive'](control/'controller-result.json',canonical({'controller_returned':False,'error':type(exc).__name__,'evidence_valid':None}));syncdir(control);raise
 c['exclusive'](control/'controller-result.json',canonical({'controller_returned':True,'observation':report,'evidence_valid':None}));syncdir(control);print(json.dumps(report,sort_keys=True))

if __name__=='__main__':
 try:main()
 except Exception as exc:print('Alpha coordinator refused: '+str(exc),file=sys.stderr);sys.exit(2)
