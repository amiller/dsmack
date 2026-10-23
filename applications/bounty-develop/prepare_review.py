#!/usr/bin/env python3
"""Prepare already selected browser CI/primary PUBLIC inputs; no VM/provider.

Trusted protected operator-selected source imports/stable namespace required.
Request/plan/suite selection and task authority are external prerequisites.
"""
import argparse,base64,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from prepare import canonical,sha,need,read,configure,SLOTS
IMAGE='sha256:71023367bea2614acd730a0c24fb15c9e195b2c4fa9c87d5abcfd243249a5390'
HARNESS='c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960'
SELECTORS={'base':'bounty-board-search-browser-review-v1','candidate':'bounty-board-search-browser-review-v1','primary-review':'bounty-board-search-primary-review-v1'}

def review_manifest(reference,raw,expected,role):
 need(role in SELECTORS,'closed review role');manifest,slots=configure(reference,raw,expected)
 manifest.update(name=SELECTORS[role],allowed_envs=[],required_envs=[],network={'mode':'none','listen_ports':[]});manifest.pop('credentials',None)
 manifest['harness']={'name':'python-application','path':'/usr/bin/python3','sha256':HARNESS,'version':'bounty-review-v1'}
 manifest['limits']['timeout_s']=540
 compose=json.loads(manifest['docker_compose_file']);service=compose['services']['develop'];service['image']='127.0.0.1:5005/dsmack-bounty-review-v1@'+IMAGE;service['security_profile']='browser-sandbox-v1'
 if 'suite'in raw:
  slots['suite']='suite';manifest['allowed_files'].append({'slot':'suite','target':'/workspace/inputs/suite','mode':'ro','audience':'workload','required':True,'max_bytes':1048576});service['volumes'].append('suite:/workspace/inputs/suite:ro')
 manifest['allowed_files'].sort(key=lambda row:row['slot']);manifest['docker_compose_file']=canonical({'services':{'review':service}}).decode();return manifest,slots

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ('public-inputs','reference-manifest','expected-reference-sha256','guest-source','application-source','expected-request-sha256','expected-stage-profile-sha256','expected-driver-sha256','expected-plan-sha256','out'):ap.add_argument('--'+n,required=True)
 a=ap.parse_args();root=Path(a.public_inputs);need(root.is_dir()and not root.is_symlink(),'ordinary selected public staging directory');names=set(x.name for x in root.iterdir());need(names in(set(SLOTS),set(SLOTS)|{'suite'}),'closed review public inputs')
 raw={k:read(root/k,8388608 if k=='source_bundle'else 4194304)for k in names};ref=read(a.reference_manifest,1048576);need(sha(ref)==a.expected_reference_sha256,'selected reference hash')
 guest=Path(a.guest_source);app=Path(a.application_source);sys.path[:0]=[str(guest/'runner-content/lib'),str(app/'applications/bounty-runtime')]
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import validate_runtime_inputs_bytes,compute_commitment
 import audit_stage
 expected=[a.expected_request_sha256,a.expected_stage_profile_sha256,a.expected_driver_sha256,a.expected_plan_sha256];paths={k:root/k if k in raw else None for k in audit_stage.SLOTS};result=audit_stage.audit(paths,*expected);role=result['role'];need(role in SELECTORS,'browser review only')
 request=result['request'];need((request['toolchain']['image_digest']if role=='primary-review'else'sha256:'+request['oci_manifest_sha256'])==IMAGE,'selected review OCI')
 need(raw['driver']==read(app/'applications/bounty-runtime/driver.py',65536),'selected image measured driver');validate_manifest_bytes(ref)
 manifest,slots=review_manifest(json.loads(ref),raw,expected,role);mr=canonical(manifest);validate_manifest_bytes(mr)
 envelope={'runtime_input_version':4,'manifest_sha256':sha(mr),'files':[{'slot':slots[k],'content_base64':base64.b64encode(raw[k]).decode()}for k in sorted(raw)],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':sorted(slots.values())},'inputs_sha256':'0'*64}}
 envelope['commitments']['inputs_sha256']=compute_commitment(envelope,manifest);er=canonical(envelope);validate_runtime_inputs_bytes(mr,er)
 out=Path(a.out);out.mkdir(mode=0o700)
 for n,b in [('compose-manifest.json',mr),('public-file-projection.json',er)]:
  with(out/n).open('xb')as f:f.write(b)
  (out/n).chmod(0o600)
 print(json.dumps({'schema':'dsmack-browser-review-public-preparation/1','selector':manifest['name'],'manifest_sha256':sha(mr),'public_projection_sha256':sha(er),'request_sha256':expected[0],'task_commitment':envelope['commitments'],'credentials_read':False,'provider_calls':False},sort_keys=True))
if __name__=='__main__':main()
