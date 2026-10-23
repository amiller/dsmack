#!/usr/bin/env python3
"""Prepare public GEN inputs only. No provider, credential, funding or VM action.

The requester policy and concrete generation plan must already be independently
selected. This constructor is a content check, not authority to spend or run.
The completed runtime envelope remains on private VDE; do not use the closed
browser-only public envelope channel.
"""
import argparse,base64,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from prepare import canonical,sha,need,read,configure,SLOTS
SELECTOR='bounty-board-search-generate-v1'
IMAGE='sha256:d91250b5d024b5b995de52e20eba57ba48f01e9562bec4562d1f88702d2d675c'
BASE_TREE='ca3ff7c4e70d33a481e672079ac381037f3940b8102f09d7c9e1d3b8ce9ab553'
def generation_manifest(reference,raw,expected):
 manifest,slots=configure(reference,raw,expected);manifest['name']=SELECTOR;manifest['harness']['version']='bounty-generator-v1'
 compose=json.loads(manifest['docker_compose_file']);service=compose['services']['develop'];service['image']='127.0.0.1:5005/dsmack-bounty-generator-v1@'+IMAGE
 manifest['docker_compose_file']=canonical({'services':{'generate':service}}).decode();return manifest,slots

def generation_request(result,expected_spec):
 r=result['request'];need(result['role']=='generate','generation-only child request')
 need(type(r['judge_index'])is int and r['judge_index']in(1,2,3),'three fixed generation indices')
 need(r['stage_id']=='generate-'+str(r['judge_index'])and r['requested_model']=='claude-opus-4-8','fixed generation role/model')
 need(r['oci_manifest_sha256']==IMAGE.split(':',1)[1]and r['source_tree_sha256']==BASE_TREE and r['input_suite_sha256']is None,'candidate-blind fixed base/image')
 need(result['stage_profile']['specification']['sha256']==expected_spec,'independently selected requester specification')

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ('public-inputs','reference-manifest','expected-reference-sha256','guest-source','application-source','expected-request-sha256','expected-stage-profile-sha256','expected-driver-sha256','expected-plan-sha256','expected-specification-sha256','out'):ap.add_argument('--'+n,required=True)
 a=ap.parse_args();root=Path(a.public_inputs);need(root.is_dir()and not root.is_symlink(),'ordinary selected public staging directory');need(set(x.name for x in root.iterdir())==set(SLOTS),'closed eight public generation inputs')
 raw={k:read(root/k,8388608 if k=='source_bundle'else 4194304)for k in SLOTS};ref=read(a.reference_manifest,1048576);need(sha(ref)==a.expected_reference_sha256,'selected reference hash')
 guest=Path(a.guest_source);app=Path(a.application_source);sys.path[:0]=[str(guest/'runner-content/lib'),str(app/'applications/bounty-runtime')]
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import compute_commitment
 import audit_stage
 expected=[a.expected_request_sha256,a.expected_stage_profile_sha256,a.expected_driver_sha256,a.expected_plan_sha256];paths={k:root/k for k in SLOTS};paths['suite']=None
 result=audit_stage.audit(paths,*expected);generation_request(result,a.expected_specification_sha256)
 need(raw['driver']==read(app/'applications/bounty-runtime/driver.py',65536),'selected image measured driver')
 validate_manifest_bytes(ref);manifest,slots=generation_manifest(json.loads(ref),raw,expected);mr=canonical(manifest);validate_manifest_bytes(mr)
 projection={'runtime_input_version':4,'manifest_sha256':sha(mr),'files':[{'slot':slots[k],'content_base64':base64.b64encode(raw[k]).decode()}for k in sorted(SLOTS)],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':sorted(slots.values())},'inputs_sha256':'0'*64}}
 projection['commitments']['inputs_sha256']=compute_commitment(projection,manifest);out=Path(a.out);out.mkdir(mode=0o700)
 for n,b in [('compose-manifest.json',mr),('public-file-projection.json',canonical(projection))]:
  with(out/n).open('xb')as f:f.write(b)
  (out/n).chmod(0o600)
 print(json.dumps({'schema':'dsmack-generation-public-preparation/1','selector':SELECTOR,'manifest_sha256':sha(mr),'public_projection_sha256':sha(canonical(projection)),'task_commitment':projection['commitments'],'request_sha256':expected[0],'judge_index':result['request']['judge_index'],'complete_private_envelope':False,'provider_calls':False,'credentials_read':False,'authority':'Independently select each generation request/plan before provider work; generated suite is an output, never prefilled.'},sort_keys=True))
if __name__=='__main__':main()
