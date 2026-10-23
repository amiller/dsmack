#!/usr/bin/env python3
"""Prepare selected develop PUBLIC bytes only; never import credentials or launch.

Trusted operator-selected source imports and a stable private staging directory are
prerequisites. This constructor does not authenticate caller authority. The output
projection is NOT a complete executable private envelope: the explicit credential
importer must later add the required broker env and validate it. Do not install a
develop envelope in the browser-only measured public-inputs channel.
"""
import argparse,base64,hashlib,json,os,stat,sys
from pathlib import Path

SLOTS=('request','task_terms','acceptance_profile','plan','stage_profile','driver','source_manifest','source_bundle')
IMAGE='sha256:f62b7a5e94a3d77affea6304deacf470cb2e9ecac27f368bbd5ed5523c207ac2'
HARNESS='304aa87a76ebb13fd22d253ac157f14980ff2cdb23e6274f3b045571405e07dc'
SELECTOR='bounty-board-search-develop-v1'
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def need(v,msg):
 if not v:raise ValueError(msg)
def read(path,cap):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size<=cap,'regular bounded single-link source')
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(cap+1)
  need(len(raw)<=cap,'source byte cap');return raw
 finally:os.close(fd)
def credential_contract():
 return {'required':True,'via':'runtime-input-broker','adapter':{'accepted_fields':['claudeAiOauth'],'profile':'claude-subscription/1','provider_route':'https://api.anthropic.com','source':'explicit-caller-stdin-or-file'}}
def configure(reference,raw,expected):
 manifest=dict(reference)
 manifest.update(name=SELECTOR,allowed_envs=[{'audience':'broker','name':'CLAUDE_SUBSCRIPTION_OAUTH'}],required_envs=['CLAUDE_SUBSCRIPTION_OAUTH'],credentials=credential_contract(),network={'mode':'nat','listen_ports':[]})
 manifest['harness']={'name':'python-application','path':'/usr/bin/python3','sha256':HARNESS,'version':'bounty-develop-r2-v1'}
 manifest['runtime_inputs']={'env':{'mode':'inject'},'stdin':{'mode':'none','max_bytes':0},'user_config':{'mode':'none','max_bytes':0}}
 manifest['limits']={'timeout_s':550,'workspace_max_bytes':67108864,'output_max_bytes':16777216}
 slots={k:k.replace('_','-')for k in SLOTS}
 manifest['allowed_files']=[{'slot':slots[k],'target':'/workspace/inputs/'+k,'mode':'ro','audience':'workload','required':True,'max_bytes':max(1048576,len(raw[k]))}for k in sorted(SLOTS)]
 argv=['/workspace/inputs/driver']
 for k,v in zip(('request','stage-profile','driver','plan'),expected):argv+=['--expected-'+k+'-sha256',v]
 service={'image':'127.0.0.1:5005/dsmack-bounty-develop-v1@'+IMAGE,'entrypoint':['/usr/bin/python3','-I','-B'],'command':argv,'read_only':True,'volumes':[slots[k]+':/workspace/inputs/'+k+':ro'for k in sorted(SLOTS)]+['state:/workspace/state:rw','artifacts:/workspace/artifacts:rw']}
 manifest['docker_compose_file']=canonical({'services':{'develop':service}}).decode()
 manifest['outputs']={'capture':['stdout','stderr'],'artifacts':[{'name':n,'path':'/workspace/artifacts/'+f}for n,f in [('result-files','result-files.tar'),('stage-checks','checks.json'),('public-input-audit','public-input-audit.json')]]}
 return manifest,slots

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ('public-inputs','reference-manifest','expected-reference-sha256','guest-source','application-source','expected-request-sha256','expected-stage-profile-sha256','expected-driver-sha256','expected-plan-sha256','out'):ap.add_argument('--'+n,required=True)
 a=ap.parse_args();root=Path(a.public_inputs);need(root.is_dir()and not root.is_symlink(),'ordinary selected public staging directory');need(set(x.name for x in root.iterdir())==set(SLOTS),'closed eight public inputs')
 raw={k:read(root/k,8388608 if k=='source_bundle'else 4194304)for k in SLOTS}
 ref=read(a.reference_manifest,1048576);need(sha(ref)==a.expected_reference_sha256,'selected reference hash')
 guest=Path(a.guest_source);app=Path(a.application_source)
 sys.path[:0]=[str(guest/'runner-content/lib'),str(app/'applications/bounty-runtime'),str(app/'applications/bounty-develop')]
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import compute_commitment
 import core
 expected=[a.expected_request_sha256,a.expected_stage_profile_sha256,a.expected_driver_sha256,a.expected_plan_sha256]
 paths={k:root/k for k in SLOTS};paths['suite']=None;result=core.audit(paths,*expected)
 need(result['request']['toolchain']=={'platform':'linux/arm64','image_digest':IMAGE},'selected develop OCI')
 need(result['request']['required_artifacts']==['public-input-audit','result-files','stage-checks'],'native three artifacts')
 need(raw['driver']==read(app/'applications/bounty-develop/driver.py',65536),'selected image driver source')
 validate_manifest_bytes(ref)
 manifest,slots=configure(json.loads(ref),raw,expected);mr=canonical(manifest);validate_manifest_bytes(mr)
 projection={'runtime_input_version':4,'manifest_sha256':sha(mr),'files':[{'slot':slots[k],'content_base64':base64.b64encode(raw[k]).decode()}for k in sorted(SLOTS)],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':sorted(slots.values())},'inputs_sha256':'0'*64}}
 projection['commitments']['inputs_sha256']=compute_commitment(projection,manifest)
 out=Path(a.out);out.mkdir(mode=0o700)
 for n,b in [('compose-manifest.json',mr),('public-file-projection.json',canonical(projection))]:
  with (out/n).open('xb')as f:f.write(b)
  (out/n).chmod(0o600)
 note={'schema':'dsmack-develop-public-preparation/1','selector':SELECTOR,'manifest_sha256':sha(mr),'public_projection_sha256':sha(canonical(projection)),'task_commitment':projection['commitments'],'request_sha256':expected[0],'complete_private_envelope':False,'credentials_read':False,'provider_calls':False,'next':'Root-selected credential importer adds broker-only CLAUDE_SUBSCRIPTION_OAUTH env, validates complete envelope, stores solely VDE envelopes/'+SELECTOR+'.envelope.json; never measured public-inputs channel'}
 (out/'PUBLIC-PREPARATION.json').write_bytes(canonical(note));print(json.dumps(note,sort_keys=True))
if __name__=='__main__':main()
