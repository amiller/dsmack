#!/usr/bin/env python3
"""Trusted local operator glue. No evidence validity or task-success claim.
Run with python3 -I. Check-only is default; execution is an explicit operation.
Policy authenticity comes ONLY from the operator's local policy tree.
"""
import base64,binascii,argparse,hashlib,importlib.util,json,os,plistlib,re,stat,subprocess,sys
from pathlib import Path
PUBLIC=('policy_path','image_manifest_path','checksum_manifest_path','metadata_path','admission_path','compose_manifest_path','workload_disk_path','scratch_template_path','result_template_path')

MODULES=('approved_run','signing_policy','session_parser','native_helper')
GATE_KEYS={'app':'approved_for_generic_app_signing_and_enrollment','helper':'approved_for_helper_adapter_integration','final':'approved_for_signing_and_live_qualification'}
RUN_FILES=('launch-spec-v3.json','envelope.json','statement.json','launch-assertion.cbor','result-assertion.cbor','launch-client-data.bin','result-client-data.bin','backend-receipt-v3.json','backend-run-result-v3.json','pair-retention.json','keyId.txt','trace.jsonl','compose-manifest.bin','admission.json','policy.json','image-manifest.json','checksum-manifest.txt','metadata.json','admitted-inputs.json','result.img','console-v3.log')
class Refused(ValueError): pass
def need(v,msg):
 if not v: raise Refused(msg)
def exact(o,keys): need(isinstance(o,dict) and set(o)==set(keys),'unexpected/missing keys')
def load_bytes(raw):
 def pairs(a):
  d={}
  for k,v in a:
   need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs)
def regular(path,private=False):
 st=os.lstat(path);need(stat.S_ISREG(st.st_mode),'regular nofollow file required')
 if private: need(st.st_uid==os.getuid() and st.st_mode&0o077==0,'private owned file required')
 return st
def pin(p):
 exact(p,('path','bytes','sha256'));need(isinstance(p['path'],str) and os.path.isabs(p['path']),'absolute pin path')
 need(type(p['bytes']) is int and p['bytes']>=0 and isinstance(p['sha256'],str) and re.fullmatch('[0-9a-f]{64}',p['sha256']),'pin shape')
 fd=os.open(p['path'],os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode),'regular public pin');h=hashlib.sha256();n=0
  while True:
   b=os.read(fd,1048576)
   if not b: break
   n+=len(b);need(n<=p['bytes'],'public length');h.update(b)
  need(n==p['bytes'] and h.hexdigest()==p['sha256'],'public pin mismatch')
 finally: os.close(fd)
 return p['path']
def document(p):
 path=pin(p);need(p['bytes']<=1048576,'document too large');return load_bytes(Path(path).read_bytes())
def modules():
 # Compile the read bytes directly so a stale __pycache__ cannot substitute code,
 # and record their digest for the helper review correspondence.
 base=Path(__file__).resolve().parent/'modulepack';out={}
 for name in MODULES:
  path=base/(name+'.py');source=path.read_bytes();spec=importlib.util.spec_from_file_location(name,path)
  m=importlib.util.module_from_spec(spec);sys.modules[name]=m;m.SOURCE_SHA256=hashlib.sha256(source).hexdigest()
  exec(compile(source,str(path),'exec'),m.__dict__);out[name]=m
 return out

def run_tool(argv):
 p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 need(p.returncode==0,'public tool refused: '+argv[0]);return p.stdout,p.stderr

def verify_app(a,sp,tool=run_tool):
 exact(a,('bundle_path','executable','info','full_cdhash','team_id','bundle_id'))
 need(a['team_id']=='DC9JH5DRMY' and a['bundle_id']=='dev.dsmack.provider','app identity')
 need(re.fullmatch('[0-9a-f]{64}',a['full_cdhash'] or ''),'full CDHash')
 bundle=Path(a['bundle_path']);need(bundle.is_absolute(),'absolute bundle')
 need(a['info']['path']==str(bundle/'Contents/Info.plist'),'Info path');i=plistlib.loads(Path(pin(a['info'])).read_bytes())
 name=i.get('CFBundleExecutable');need(isinstance(name,str) and re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}',name),'executable selection')
 need(i.get('CFBundleIdentifier')==a['bundle_id'],'bundle identifier')
 need(a['executable']['path']==str(bundle/'Contents/MacOS'/name),'executable path');exe=pin(a['executable'])
 arch,_=tool(['/usr/bin/lipo','-archs',exe]);need(arch.strip()==b'arm64','exact arm64 executable')
 tool(['/usr/bin/codesign','--verify','--deep','--strict',str(bundle)])
 out,err=tool(['/usr/bin/codesign','-d','--verbose=4',str(bundle)])
 metadata=(out+err).decode('utf-8');checked=sp.check_metadata(metadata,a['team_id'],a['bundle_id'])
 need(checked['cdhash_full']==a['full_cdhash'],'signed full CDHash mismatch')
 out,err=tool(['/usr/bin/codesign','-d','--entitlements',':-',str(bundle)])
 sp.check_entitlements_version(out,sp.POLICY_VERSION_HVF,a['team_id'],a['bundle_id'])
 return metadata

def checked_string(v,cap):
 need(isinstance(v,str) and 0<len(v)<=cap and '\x00' not in v,'bounded nonempty string')
def hex64(v):need(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v),'hex64')
def b64_32(v,cap):
 need(isinstance(v,str) and len(v)<=cap,'base64 bound')
 try:raw=base64.b64decode(v,validate=True)
 except (ValueError,binascii.Error):raise Refused('strict base64')
 need(len(raw)==32 and base64.b64encode(raw).decode()==v,'canonical 32-byte base64')
def checker_schema(c):
 # Faithful bounded /3-only subset of actual cross schemas.validate_checker_context.
 # Only production single-selector demo policies are admitted below.
 exact(c,('schema','verifier_id','verifier_version','report_verify_key_b64','report_key_id','core_sha256','extractor_tool_sha256','expected'))
 need(c['schema']=='dsmack.runresult-checker-context/3' and c['verifier_id']=='dsmack-runresult-verifier','checker schema/verifier')
 checked_string(c['verifier_version'],16);checked_string(c['report_key_id'],128);b64_32(c['report_verify_key_b64'],64)
 hex64(c['core_sha256']);hex64(c['extractor_tool_sha256'])
 need(c['core_sha256']=='13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5','pinned core')
 e=c['expected'];exact(e,('challenge','manifest_sha256','receipt_selector','key_id_b64','enrollment_class','app_id','team_id','environment','workload_status','exit_code','receipt_environment','closure_context','selector_manifests'))
 for k,cap in (('challenge',4096),('app_id',256),('team_id',64),('environment',32),('receipt_environment',32)):checked_string(e[k],cap)
 hex64(e['manifest_sha256']);b64_32(e['key_id_b64'],60)
 need(isinstance(e['receipt_selector'],str) and re.fullmatch('[a-z][a-z0-9-]{0,62}',e['receipt_selector']),'selector grammar')
 need(e['enrollment_class']=='apple-appattest-production' and e['workload_status'] in ('completed','failed','cancelled') and type(e['exit_code']) is int,'expected enrollment/outcome')
 x=e['closure_context'];exact(x,('schema','attempt_id','selectors'));need(x['schema']=='dsmack-result-closure-context/1' and isinstance(x['attempt_id'],str) and re.fullmatch('[0-9a-f]{32}',x['attempt_id']),'closure schema/attempt')
 names=x['selectors'];need(isinstance(names,list) and 1<=len(names)<=32,'closure count')
 for n in names:need(isinstance(n,str) and 1<=len(n)<=128 and all(33<=ord(k)<=126 and k not in '/\\' for k in n),'closure name')
 need(names==sorted(set(names)) and len(json.dumps(x,sort_keys=True,separators=(',',':')).encode())<=8192 and e['receipt_selector'] in names,'closure order/size/primary')
 manifests=e['selector_manifests'];need(isinstance(manifests,dict) and set(manifests)==set(names),'selector membership')
 for n,v in manifests.items():
  need(re.fullmatch('[a-z][a-z0-9-]{0,62}',n),'selector grammar');exact(v,('manifest_sha256','workload_status','exit_code','receipt_environment'));hex64(v['manifest_sha256']);need(v['workload_status'] in ('completed','failed','cancelled') and type(v['exit_code']) is int,'selector outcome');checked_string(v['receipt_environment'],32)
 need(all(manifests[e['receipt_selector']][k]==e[k] for k in manifests[e['receipt_selector']]),'primary mismatch')
 return c

def relationships(p,m,gates):
 b=p['bindings'];exact(b,('signing_record','unsigned_executable','candidate_source_manifest','native_archive','helper_compile','helper_inventory','final_handoff'))
 for k in ('unsigned_executable','candidate_source_manifest','native_archive','final_handoff'):pin(b[k])
 a=gates['app'].get('exact_candidate_pins',{});need(isinstance(a,dict),'actual app pins')
 for role,key in (('unsigned_executable','unsigned_executable'),('candidate_source_manifest','candidate_source_manifest'),('native_archive','native_archive')):
  need(a.get(key)==b[role]['sha256'],'app review source/unsigned/native relationship')
 need(a.get('unsigned_executable_bytes')==b['unsigned_executable']['bytes'] and a.get('native_archive_bytes')==b['native_archive']['bytes'],'app review lengths')
 need(a.get('info_plist')==p['app']['info']['sha256'],'reviewed Info.plist')
 sign=document(b['signing_record']);exact(sign,('schema','app_review','unsigned_executable','signed_executable','info_plist','native_archive','candidate_source_manifest','full_cdhash'))
 need(sign['schema']=='dsmack-local-signing-operation/1','documented local signing operation')
 for k,v in (('app_review',p['reviews']['app']),('unsigned_executable',b['unsigned_executable']),('signed_executable',p['app']['executable']),('info_plist',p['app']['info']),('native_archive',b['native_archive']),('candidate_source_manifest',b['candidate_source_manifest'])):need(sign[k]==v,'signing correspondence '+k)
 need(sign['full_cdhash']==p['app']['full_cdhash'],'signing CDHash correspondence')
 comp=document(b['helper_compile']);need(comp.get('schema')=='dsmack-repaired-helper-compile/1' and type(comp.get('actual_link_exit')) is int and comp['actual_link_exit']==0,'actual helper link')
 art=comp.get('mini_actual_artifact',{});need(all(art.get(k)==p['helper']['launcher'][k] for k in ('path','bytes','sha256')),'actual helper artifact correspondence')
 inv=document(b['helper_inventory']);need(comp.get('source_inventory_sha256')==b['helper_inventory']['sha256'],'compiled helper inventory correspondence')
 hp=gates['helper'].get('exact_candidate_pins',{}).get('sha256',{});need(isinstance(hp,dict),'actual helper source review pins')
 for f in ('src/lib.rs','src/main.rs','Cargo.lock','Cargo.toml'):
  need(isinstance(inv.get(f),str) and hp.get('candidate/gvproxy-launcher/'+f)==inv[f],'compiled helper reviewed source '+f)
 need(hp.get('candidate/aux/bin/native_helper.py')==m['native_helper'].SOURCE_SHA256,'selected reviewed adapter')
 # Concrete local final-review metadata contract, not an attestation schema.
 final=document(b['final_handoff'])
 need(gates['final'].get('exact_candidate_pins',{}).get('selected_handoff_sha256')==b['final_handoff']['sha256'],'original final review selected handoff')
 need(final.get('runtime_public_inputs')==p['inputs'],'final reviewed runtime public inputs')
 need(final.get('helper_compile_handoff')==b['helper_compile'],'final reviewed helper compile')
 need(final.get('gvproxy')==p['helper']['gvproxy'],'final reviewed upstream gvproxy pairing')
 need(final.get('unsigned_binary_sha256')==a.get('unsigned_executable') and final.get('native_archive_sha256')==a.get('native_archive'),'final reviewed app/native correspondence')
 own=final.get('coordinator_source',{});pin(own);need(own['path']==str(Path(__file__).resolve()),'actual selected coordinator source path')

def execution_profile(final,s,inputs):
 # ONLY a raw independently reviewed final handoff can select this extension.
 # Labels describe reviewed workload bytes; they do not configure model/network.
 q=final.get('execution_profile')
 if 'execution_profile' not in final:
  need(type(s['runtime_seconds']) is int and s['runtime_seconds']==600 and s['profile']=='mini-4096','qualified runtime/profile')
  need(s['workload_id']=='claude-coding-task-subscription-dstack','selected workload')
  return 1073741824,268435456,1073741824
 exact(q,('schema','profile_id','workload_id','resource_profile','memory_mib','vcpus','runtime_seconds','scratch_template_bytes','result_template_bytes','compose_manifest_sha256','model_profile','security_preset'))
 need(q['schema']=='dsmack-protected-execution-profile/1','execution profile schema')
 allowed={'claude-broker-diagnostic-v1':4294967296,'bounty-board-search-generate-v1':4294967296,'bounty-board-search-develop-v1':4294967296,'bounty-board-search-primary-review-v1':4294967296,'bounty-board-search-browser-review-v1':4294967296,'codex-private-sample':1073741824}
 need(isinstance(q['profile_id'],str) and q['profile_id'] in allowed,'reviewed execution profile ID')
 need(q['workload_id']==q['profile_id']==s['workload_id'],'execution profile workload')
 need(q['resource_profile']==s['profile']=='mini-4096','execution resource profile')
 for key,want in (('memory_mib',4096),('vcpus',1),('runtime_seconds',600),('scratch_template_bytes',allowed[q['profile_id']]),('result_template_bytes',268435456)):
  need(type(q[key]) is int and q[key]==want,'execution profile '+key)
 need(type(s['runtime_seconds']) is int and s['runtime_seconds']==q['runtime_seconds'],'execution runtime')
 need(q['compose_manifest_sha256']==inputs['compose_manifest_path']['sha256'],'execution workload bytes')
 for key in ('model_profile','security_preset'):
  need(isinstance(q[key],str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/-]{0,127}',q[key]) is not None,'reviewed '+key+' identifier')
 if q['profile_id']=='claude-broker-diagnostic-v1':need(q['model_profile']=='none' and q['security_preset']=='none','Closed diagnostic tuple')
 if q['profile_id'] in ('bounty-board-search-develop-v1','bounty-board-search-generate-v1'):need(q['model_profile']=='claude-opus-4-8' and q['security_preset']=='none','Closed develop model/security tuple')
 return q['scratch_template_bytes'],q['result_template_bytes'],q['scratch_template_bytes']

def credential_free_profile(final):
 q=final.get('execution_profile')
 return isinstance(q,dict) and q.get('profile_id') in ('bounty-board-search-browser-review-v1','bounty-board-search-primary-review-v1') and q.get('model_profile')=='none'

def validate(p,m,mode,tool=run_tool,*,check_only=False):
 exact(p,('schema','status','reviews','bindings','app','inputs','spec','embedded','closure_context','checker_context','helper','out_parent','out_name','challenge','key_id'))
 need(p['schema']=='dsmack-protected-local-coordinator/1' and p['status']=='ready','operator policy incomplete')
 exact(p['reviews'],GATE_KEYS);gates={}
 for role,key in GATE_KEYS.items():
  gates[role]=document(p['reviews'][role]);approved=gates[role].get(key) is True
  if role=='final' and check_only: approved=approved or gates[role].get('approved_for_check_only') is True
  need(approved,role+' independent original review not approved')
 relationships(p,m,gates)
 return _validate_runtime(p,m,mode,document(p['bindings']['final_handoff']),tool=tool)

def checker_outcome(outcome):
 need(type(outcome) is tuple and len(outcome)==2 and type(outcome[0]) is str and type(outcome[1]) is int and outcome in (('completed',0),('failed',1)),'closed checker outcome')
 return {'workload_status':outcome[0],'exit_code':outcome[1]}

def _validate_runtime(p,m,mode,final,tool=run_tool,app_verifier=verify_app,*,expected_outcome=('completed',0)):
 # Shared mechanics only; each entrypoint must authenticate its own admission
 # before calling. Default engineering entry retains all original review checks.
 outcome=checker_outcome(expected_outcome)
 metadata=app_verifier(p['app'],m['signing_policy'],tool)
 exact(p['inputs'],PUBLIC)
 for k in PUBLIC: pin(p['inputs'][k])
 s=p['spec'];exact(s,(*PUBLIC,'profile','workload_id','runtime_seconds','private_input_path','net_socket_path'))
 for k in PUBLIC: need(s[k]==p['inputs'][k]['path'],'spec/input mismatch')
 scratch_bytes,result_bytes,scratch_cap=execution_profile(final,s,p['inputs'])
 if 'execution_profile' in final:
  need(document(p['inputs']['compose_manifest_path']).get('name')==s['workload_id'],'execution manifest name')
 selected_image=final.get('selected_image');hex64(selected_image)
 manifest=document(p['inputs']['image_manifest_path']);need(manifest.get('arch')=='aarch64' and manifest.get('image_id')==selected_image,'selected ARM64 image')
 r=manifest.get('resource_profiles',{}).get(s['profile'],{});need(type(r.get('mem_mib')) is int and r['mem_mib']==4096 and type(r.get('vcpus')) is int and r['vcpus']==1,'measured profile')
 exact(p['embedded'],('kernel','initrd','system_disk'))
 for k in p['embedded']:
  pin(p['embedded'][k]);need(all(manifest.get(k,{}).get(x)==p['embedded'][k][x] for x in ('path','bytes','sha256')),'embedded image mismatch')
 policy=document(p['inputs']['policy_path']);limits=policy.get('resource_limits',{})
 need(any(x.get('image_id')==selected_image and x.get('manifest_sha256')==p['inputs']['image_manifest_path']['sha256'] for x in policy.get('admitted_images',[])),'base admission binding')
 for k,n in (('max_mem_mib',4096),('max_vcpus',1),('max_runtime_seconds',600)):
  need(type(limits.get(k)) is int and limits[k]>=n,'admission resource bound')
 need(p['inputs']['scratch_template_path']['bytes']==scratch_bytes and p['inputs']['result_template_path']['bytes']==result_bytes,'exact qualified template sizes')
 c=document(p['closure_context']);need(set(c)=={'schema','attempt_id','selectors'} and c['schema']=='dsmack-result-closure-context/1' and re.fullmatch('[0-9a-f]{32}',c['attempt_id'] or '') and c['selectors']==[s['workload_id']],'closure context shape')
 need(Path(p['closure_context']['path']).read_bytes()==m['session_parser'].canonical_bytes(c),'canonical closure context')
 checker=checker_schema(document(p['checker_context']));exact(checker,('schema','verifier_id','verifier_version','report_verify_key_b64','report_key_id','core_sha256','extractor_tool_sha256','expected'))
 need(checker['schema']=='dsmack.runresult-checker-context/3','actual checker context version')
 e=checker['expected'];need(isinstance(e,dict) and e.get('closure_context')==c,'checker independently expected full closure context')
 expected={'enrollment_class':'apple-appattest-production','app_id':'DC9JH5DRMY.dev.dsmack.provider','team_id':'DC9JH5DRMY','environment':'production','receipt_environment':'vm',**outcome,'receipt_selector':s['workload_id'],'manifest_sha256':p['inputs']['compose_manifest_path']['sha256']}
 for k,v in expected.items(): need(e.get(k)==v and type(e.get(k)) is type(v),'checker actual external expected '+k)
 selector_expected={s['workload_id']:{k:expected[k] for k in ('manifest_sha256','workload_status','exit_code','receipt_environment')}}
 need(e.get('selector_manifests')==selector_expected and type(e.get('selector_manifests',{}).get(s['workload_id'],{}).get('exit_code')) is int,'checker exact selected outcome policy')
 ch=Path(pin(p['challenge'])).read_bytes();need(len(ch)==32,'32-byte root ceremony challenge')
 if mode=='run': need(checker.get('expected',{}).get('challenge')==ch.hex(),'checker independently expected challenge')
 if mode=='run':
  kid=Path(pin(p['key_id'])).read_bytes();need(1<=len(kid)<=1024 and bool(kid.decode('utf-8').strip()) and kid.decode('utf-8')==kid.decode('utf-8').strip(),'actual enrollment keyID')
  need(checker.get('expected',{}).get('key_id_b64')==kid.decode('utf-8'),'checker independently expected enrollment keyID')
  # Private payload content is intentionally NEVER read, hashed or inventoried.
  if credential_free_profile(final):
   need(s['private_input_path']=='','credential-free profile forbids private input')
  else:
   need(os.path.isabs(s['private_input_path']),'private path');st=regular(s['private_input_path'],True)
   if final.get('execution_profile',{}).get('profile_id') in ('bounty-board-search-develop-v1','bounty-board-search-generate-v1','claude-broker-diagnostic-v1'):
    need(st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=min(1073741824,scratch_bytes),'Develop private metadata/cap')
 exact(p['helper'],('launcher','gvproxy','run_dir'))
 for k in ('launcher','gvproxy'): pin(p['helper'][k])
 parent=Path(p['out_parent']);need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,100}',p['out_name'] or ''),'fresh output name')
 out=parent/p['out_name'];need(not os.path.lexists(out),'output collision')
 helper=parent/(p['out_name']+'.helper');need(p['helper']['run_dir']==str(helper) and not os.path.lexists(helper),'fresh owned helper namespace')
 need(s['net_socket_path']==str(helper/'net.sock'),'helper socket path')
 session={k:s[k] for k in PUBLIC};session.update({k:s[k] for k in ('profile','workload_id','runtime_seconds','private_input_path','net_socket_path')})
 session.update(schema=m['session_parser'].V3_SESSION_SCHEMA,workload_sha256=p['inputs']['workload_disk_path']['sha256'])
 for role in ('scratch','result'):
  session[role+'_template_sha256']=p['inputs'][role+'_template_path']['sha256'];session[role+'_template_bytes']=p['inputs'][role+'_template_path']['bytes']
 raw=m['session_parser'].canonical_bytes(session);m['session_parser'].parse_session_bytes(raw,scratch_max_bytes=scratch_cap)
 return out,raw,metadata

def exclusive(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  v=memoryview(raw)
  while v:
   n=os.write(fd,v);need(n>0,'short write');v=v[n:]
  os.fsync(fd)
 finally: os.close(fd)

def execute(p,m,mode,validated,tool=None,helper_class=None):
 # A read-only validation result can never authorize process or file side effects.
 need(document(p['reviews']['final']).get(GATE_KEYS['final']) is True,'live final approval required for execute')
 return _execute_runtime(p,m,mode,validated,tool=tool,helper_class=helper_class)

def _execute_runtime(p,m,mode,validated,tool=None,helper_class=None):
 # Called only after the entrypoint's independent authority recheck.
 out,raw,metadata=validated;parent=out.parent
 # Established protected operator directory, fresh exclusive children only.
 # Same-UID/root path mutation is outside this local operator trust boundary.
 logs=parent/(p['out_name']+'.logs');session=parent/(p['out_name']+'.session.json')
 need(not os.path.lexists(logs) and not os.path.lexists(session) and not os.path.lexists(out),'launch path collision')
 os.mkdir(logs,0o700);exclusive(session,raw);exclusive(logs/'codesign-metadata.txt',metadata.encode())
 report={'schema':'dsmack-local-launch-observation/1','mode':mode,'evidence_valid':None,'task_success':None,'launchservices_returncode':None,'output_complete':False,'helper':None,'errors':[]}
 h=None
 try:
  if mode=='run':
   h=(helper_class or m['native_helper'].Helper)(p['helper'],logs);h.start()
  argv=['/usr/bin/open','-n','-W','--stdout',str(logs/'stdout.txt'),'--stderr',str(logs/'stderr.txt'),p['app']['bundle_path'],'--args']
  if mode=='enroll': argv+=['enroll',str(out),p['challenge']['path']]
  else: argv+=['hvf-v3',str(out),str(session),p['challenge']['path'],p['key_id']['path']]
  proc=(tool or subprocess.run)(argv,timeout=1320);report['launchservices_returncode']=proc.returncode
  need(proc.returncode==0,'LaunchServices nonzero')
  files=('keyId.txt','clientData.bin','attestation.cbor') if mode=='enroll' else RUN_FILES
  for name in files: need(regular(out/name).st_size>0,'missing/empty retained output '+name)
  if mode=='enroll':
   challenge=Path(pin(p['challenge'])).read_bytes();need(len(challenge)==32,'enroll challenge changed')
   expected=m['session_parser'].canonical_bytes({'domain':'minimal-attested-run-enroll/1','challenge':challenge.hex()})
   need((out/'clientData.bin').read_bytes()==expected,'actual enrollment clientData differs from prechosen challenge')
  report['output_complete']=True
 except BaseException as exc:
  report['errors'].append(type(exc).__name__+': '+str(exc))
 finally:
  if h is not None:
   try:
    report['helper']=h.stop();need(report['helper'].get('quiescence')=='native-confirmed' and not report['helper'].get('cleanup_errors'),'helper stop unconfirmed')
   except BaseException as exc: report['errors'].append('helper stop: '+str(exc))
  exclusive(logs/'launch-observation.json',json.dumps(report,sort_keys=True).encode())
 need(not report['errors'],'launch incomplete; retained partial observation '+str(logs/'launch-observation.json'))
 return report

def main():
 a=argparse.ArgumentParser();a.add_argument('--policy',required=True);a.add_argument('--mode',choices=('enroll','run'),required=True);g=a.add_mutually_exclusive_group();g.add_argument('--execute',action='store_true');g.add_argument('--check-only',action='store_true');x=a.parse_args()
 p=load_bytes(Path(x.policy).read_bytes());m=modules();v=validate(p,m,x.mode,check_only=not x.execute)
 if x.execute: result=execute(p,m,x.mode,v)
 else: result={'checked':True,'executed':False,'evidence_valid':None,'task_success':None}
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try: main()
 except Exception as exc: print('coordinator refused: '+str(exc),file=sys.stderr);sys.exit(2)
