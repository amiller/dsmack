#!/usr/bin/env python3
"""Prepare a NONFUNDED full14 native qualification; no VM or provider call.

Operator-selected source/OCI/guest paths are trusted staging inputs. This tool
validates native contracts and application audit but grants no task authority.
"""
import argparse,base64,hashlib,json,shutil,sys,types
from pathlib import Path

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ('artifacts','guest-source','reference-manifest','oci-layout','source-packet','application-source','attempt-id','out'):ap.add_argument('--'+n,required=True)
 a=ap.parse_args();out=Path(a.out);out.mkdir(mode=0o700);guest=Path(a.guest_source);app=Path(a.application_source);packet=Path(a.source_packet)
 if len(a.attempt_id)!=32 or any(c not in '0123456789abcdef'for c in a.attempt_id):raise ValueError('attempt ID')
 sys.path[:0]=[str(guest/'runner-content/lib'),str(guest/'runner-content'),str(app/'applications/bounty-runtime')]
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import validate_runtime_inputs_bytes,compute_commitment
 from dsmack_guest_io.public_inputs import choose
 import audit_stage
 module=guest/'build/make_guest_inputs.py';gi=types.ModuleType('selected_guest_inputs');gi.__file__=str(module);exec(compile(module.read_bytes(),str(module),'exec'),gi.__dict__)
 facts=gi.bundle_facts(a.artifacts);manifest=gi.new_manifest(a.reference_manifest,facts,no_limits=True);name='bounty-board-search-primary-review-v1'
 delivery=gi.stage_oci_layout(str(out),a.oci_layout,repo_name='dsmack-bounty-primary-v1');image=delivery['refs']['dsmack-bounty-primary-v1'];digest=image.split('@',1)[1]
 terms=canonical({'schema':'dsmack-native-qualification-terms/1','scope':'NONFUNDED FULL14 QUALIFICATION ONLY','eligibility':False,'checks':'4 original browser + 4 original logic (80 cases) + 6 features','candidate':'exploratory PR44 reconstruction; no author acknowledgement or reward claim'})
 profile=canonical({'schema':'dsmack-native-primary-qualification-profile/1','scope':'NONFUNDED; NOT FULL TEN-STAGE ACCEPTANCE','oci_manifest_sha256':digest.split(':',1)[1],'coverage_sha256':sha((app/'applications/bounty-judges/primary-logic-coverage.json').read_bytes())})
 plan=canonical({'schema':'dsmack-native-primary-qualification-plan/1','task_terms_sha256':sha(terms),'acceptance_profile_sha256':sha(profile),'stage':'primary','provider_calls':False,'funded':False})
 transform=json.loads((packet/'transform.json').read_bytes());stage=canonical({'schema':'dsmack-native-primary-stage-profile/1','admission_transform':{'record':transform,'sha256':sha(canonical(transform))},'specification':None,'scope':'NONFUNDED QUALIFICATION'})
 trees=json.loads((packet/'PACKET-IDENTITIES.json').read_bytes())['trees'];driver=(app/'applications/bounty-runtime/driver.py').read_bytes()
 request={'schema':'dsmack-bounty-public-request/1','task_id':'nonfunded-full14-qualification','task_terms_sha256':sha(terms),'attempt_id':a.attempt_id,'attempt_nonce':sha(('NONFUNDED-APPLICATION-NONCE:'+a.attempt_id).encode()),'run_id':a.attempt_id+'-primary','run_role':'review','acceptance_profile_sha256':sha(profile),'base':{'repo':'https://github.com/amiller/bounty-arcade','commit':'5c76d40e77db1f4864dabd4b9398d02589cff330','tree_manifest_sha256':trees['base']},'candidate':{'upstream_commit':None,'tree_manifest_sha256':trees['candidate'],'admission_transform_sha256':sha(canonical(transform))},'toolchain':{'platform':'linux/arm64','image_digest':digest},'required_artifacts':['public-input-audit','result-files','stage-checks']}
 raw={'request':canonical(request),'task_terms':terms,'acceptance_profile':profile,'plan':plan,'stage_profile':stage,'driver':driver,'source_manifest':(packet/'candidate.manifest.json').read_bytes(),'source_bundle':(packet/'candidate.tar').read_bytes()}
 expected=[sha(b'dsmack-bounty-public-request/1\0'+raw['request']),sha(stage),sha(driver),sha(plan)]
 inputs=out/'qualification-inputs';inputs.mkdir()
 for k,v in raw.items():(inputs/k).write_bytes(v)
 audit_stage.audit({k:(inputs/k if k in raw else None)for k in audit_stage.SLOTS},*expected)
 manifest.update(name=name,allowed_envs=[],required_envs=[],network={'mode':'none','listen_ports':[]});manifest.pop('credentials',None)
 manifest['harness']={'name':'python-application','path':'/usr/bin/python3','sha256':'c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960','version':'full14-qualification-v1'}
 manifest['runtime_inputs']={'env':{'mode':'inject'},'stdin':{'mode':'none','max_bytes':0},'user_config':{'mode':'none','max_bytes':0}}
 manifest['limits']={'timeout_s':540,'workspace_max_bytes':67108864,'output_max_bytes':16777216}
 slots={k:k.replace('_','-')for k in raw};manifest['allowed_files']=[{'slot':slots[k],'target':'/workspace/inputs/'+k,'mode':'ro','audience':'workload','required':True,'max_bytes':max(1048576,len(raw[k]))}for k in sorted(raw)]
 argv=['/workspace/inputs/driver']
 for k,v in zip(('request','stage-profile','driver','plan'),expected):argv+=['--expected-'+k+'-sha256',v]
 service={'image':image,'entrypoint':['/usr/bin/python3','-I','-B'],'command':argv,'read_only':True,'security_profile':'browser-sandbox-v1','volumes':[slots[k]+':/workspace/inputs/'+k+':ro'for k in sorted(raw)]+['state:/workspace/state:rw','artifacts:/workspace/artifacts:rw']}
 manifest['docker_compose_file']=canonical({'services':{'primary':service}}).decode();manifest['outputs']={'capture':['stdout','stderr'],'artifacts':[{'name':n,'path':'/workspace/artifacts/'+f}for n,f in [('result-files','result-files.tar'),('stage-checks','checks.json'),('public-input-audit','public-input-audit.json')]]}
 mr=canonical(manifest);validate_manifest_bytes(mr)
 envelope={'runtime_input_version':4,'manifest_sha256':sha(mr),'files':[{'slot':slots[k],'content_base64':base64.b64encode(v).decode()}for k,v in sorted(raw.items())],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':sorted(slots.values())},'inputs_sha256':'0'*64}}
 envelope['commitments']['inputs_sha256']=compute_commitment(envelope,manifest);er=canonical(envelope);validate_runtime_inputs_bytes(mr,er)
 for n in ('manifests','public-inputs','admission','base-bundle','closure-context'):(out/n).mkdir(exist_ok=True)
 (out/'manifests'/(name+'.app-compose.json')).write_bytes(mr);(out/'public-inputs'/(name+'.envelope.json')).write_bytes(er);choose(out/'public-inputs',out/'manifests'/(name+'.app-compose.json'),out/'absent-private')
 for n in ('Image','initramfs.cpio.gz','metadata.json','rootfs.squashfs.verity','sha256sum.txt'):shutil.copyfile(Path(a.artifacts)/n,out/'base-bundle'/n)
 (out/'admission/base-admission.json').write_bytes(canonical({'admission_version':1,'allowed_os_image_hashes':[facts['os_image_hash']]}))
 (out/'closure-context/context.json').write_bytes(canonical({'schema':'dsmack-result-closure-context/1','attempt_id':a.attempt_id,'selectors':[name]}));(out/'WORKLOAD').write_text(name+'\n')
 # qualification-inputs is retained separately, never an unrecognized public channel.
 shutil.move(str(inputs),str(out.parent/(out.name+'-retained-inputs')))
 print(json.dumps({'selector':name,'manifest_sha256':sha(mr),'envelope_sha256':sha(er),'task_commitment':envelope['commitments'],'expected_request_sha256':expected[0],'image':image,'os_image_hash':facts['os_image_hash'],'funded':False,'full_ten_stage_acceptance':False},sort_keys=True))
if __name__=='__main__':main()
