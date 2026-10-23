#!/usr/bin/env python3
"""Zed-only heavy PUBLIC review disk preparation; no credentials/VM/provider.

Copies the selected710 OCI into this disk; never relies on Zed's registry.
Source imports are operator-selected trusted inputs in a stable namespace.
The original qualified transport and OCI helpers are loaded from exact raw
source, not cached bytecode. Real task admission remains external authority.
"""
import argparse,base64,hashlib,json,os,shutil,sys,tarfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from prepare import read,need,canonical,sha
from prepare_review import IMAGE,SELECTORS
from transport_loader import load,execute,raw
CONFIG='sha256:e36eaa11c766eb715dab6ba41dc82d046365d408175506e0cce55e006adbd06b'
EXTERNAL={'closure.py':'8ed11fbb5b64e313463d2f24c527a570364a32675140cd8fadd00cca9888b54f','oci_publish.py':'d68fca5d394c3a934cfb3b66485534cd9051c67a10266be8f61a83879940b676','make_guest_inputs.py':'69a2e7c310a91f3b327d9ef859a941b84a500c9c3ac664be4d8d5f9e37a17537'}
def file_sha(path):
 h=hashlib.sha256()
 with open(path,'rb')as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
ORIGINAL_PUBLIC_CHANNELS=('manifests','admission','base-bundle','images','commitments','oci-layout','closure-context')
def enable_public_envelope_channel(transport):
 need(transport.PUBLIC_CHANNELS==ORIGINAL_PUBLIC_CHANNELS,'exact original public transport channel closure')
 need(transport.PRIVATE_CHANNELS==('envelopes','broker'),'exact separate private transport channels')
 transport.PUBLIC_CHANNELS=ORIGINAL_PUBLIC_CHANNELS+('public-inputs',)
def verify_packed_public_envelope(path,selector,expected):
 target='public-inputs/'+selector+'.envelope.json';found=0;count=0
 # Read the actual packed output, never merely the staging tree. The separate
 # prelaunch scanner remains the complete hostile-archive grammar authority.
 with tarfile.open(path,'r|')as archive:
  for member in archive:
   count+=1;need(count<=4096,'packed public member bound')
   need(member.name.split('/')[0]not in ('envelopes','broker'),'packed private channel refused')
   if member.name==target:
    found+=1;need(found==1 and member.isfile()and member.size==len(expected),'one packed regular selected public envelope')
    stream=archive.extractfile(member);need(stream is not None and stream.read(len(expected)+1)==expected,'packed public envelope bytes differ')
 need(found==1,'selected public envelope missing from packed disk')
 return sha(expected)
def execution_context(projection,execution_attempt_id,selector):
 need(len(execution_attempt_id)==32 and all(c in '0123456789abcdef'for c in execution_attempt_id),'32-hex selected native execution ID')
 slots=[x for x in projection['files']if x['slot']=='request'];need(len(slots)==1,'single public request slot')
 request=json.loads(base64.b64decode(slots[0]['content_base64'],validate=True))
 need(request['run_id']==execution_attempt_id and request['attempt_id']!=execution_attempt_id,'selected native execution ID equals S0 run_id, distinct from assignment')
 return request,{'schema':'dsmack-result-closure-context/1','attempt_id':execution_attempt_id,'selectors':[selector]}

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ('preparation','expected-manifest-sha256','expected-projection-sha256','guest-source','transport-module','artifacts','expected-checksum-sha256','oci-layout','execution-attempt-id','out'):ap.add_argument('--'+n,required=True)
 a=ap.parse_args();need(sys.flags.isolated==1 and sys.platform=='linux','isolated Linux build required');out=Path(a.out);need(out.is_absolute()and str(out).startswith('/data/'),'heavy preparation belongs on Zed /data')
 prep=Path(a.preparation);mr=read(prep/'compose-manifest.json',1048576);pr=read(prep/'public-file-projection.json',33554432);need(sha(mr)==a.expected_manifest_sha256 and sha(pr)==a.expected_projection_sha256,'selected public source pins')
 manifest=json.loads(mr);projection=json.loads(pr);selector=manifest['name'];need(selector in SELECTORS.values() and projection['manifest_sha256']==sha(mr),'selected review manifest')
 request,context=execution_context(projection,a.execution_attempt_id,selector)
 guest=Path(a.guest_source);sys.path.insert(0,str(guest/'runner-content/lib'))
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import compute_commitment
 validate_manifest_bytes(mr);need(compute_commitment(projection,manifest)==projection['commitments']['inputs_sha256'],'selected public commitment')
 transport=load(a.transport_module);enable_public_envelope_channel(transport);package=sys.modules['dsmack_guest_io']
 for n in ('closure','oci_publish'):
  path=guest/'runner-content/dsmack_guest_io'/(n+'.py');setattr(package,n,execute('dsmack_guest_io.'+n,path,raw(path,EXTERNAL[n+'.py'])))
 path=guest/'build/make_guest_inputs.py';gi=execute('selected_original_guest_input_builder',path,raw(path,EXTERNAL[path.name]))
 out.mkdir(mode=0o700);tree=out/'public-tree';tree.mkdir(mode=0o700)
 for n in ('manifests','admission','base-bundle','commitments','closure-context','public-inputs'):(tree/n).mkdir()
 (tree/'manifests'/(selector+'.app-compose.json')).write_bytes(mr)
 base=manifest['base_vm'];art=Path(a.artifacts)
 for n,field in [('Image','kernel_sha256'),('initramfs.cpio.gz','initrd_sha256'),('rootfs.squashfs.verity','rootfs_sha256'),('metadata.json','metadata_sha256')]:
  need(not(art/n).is_symlink()and (art/n).is_file()and file_sha(art/n)==base[field],'selected base artifact identity');shutil.copyfile(art/n,tree/'base-bundle'/n);need(file_sha(tree/'base-bundle'/n)==base[field],'copied base artifact identity')
 checksum=read(art/'sha256sum.txt',65536);need(sha(checksum)==a.expected_checksum_sha256,'selected checksum manifest');(tree/'base-bundle/sha256sum.txt').write_bytes(checksum)
 (tree/'admission/base-admission.json').write_bytes(canonical({'admission_version':1,'allowed_os_image_hashes':[base['os_image_hash']]}))
 gi.emit_commitment_declaration(str(tree),selector,projection,sha(mr))
 role='primary-review'if request['schema']=='dsmack-bounty-public-request/1'else request.get('role');need(role in SELECTORS and selector==SELECTORS[role],'closed request role/selector');need(manifest['network']['mode']=='none'and not manifest.get('credentials',{}).get('required')and not manifest['allowed_envs']and not manifest['required_envs'],'credential-free browser channel')
 (tree/'closure-context/context.json').write_bytes(canonical(context));(tree/'WORKLOAD').write_text(selector+'\n')
 delivery=gi.stage_oci_layout(str(tree),a.oci_layout,repo_name='dsmack-bounty-review-v1');need(delivery['content_digest_preserved']==IMAGE,'actual review OCI on disk')
 services=json.loads(manifest['docker_compose_file'])['services'];need(len(services)==1 and next(iter(services.values()))['image']==delivery['refs']['dsmack-bounty-review-v1'],'manifest consumes staged cold-loopback OCI')
 blob=tree/'oci-layout/blobs/sha256'/IMAGE.split(':')[1];oci_manifest=json.loads(blob.read_bytes());need(oci_manifest['config']['digest']==CONFIG,'actual review config on disk')
 # Public files-only envelope is admitted by the unchanged measured browser channel.
 (tree/'public-inputs'/(selector+'.envelope.json')).write_bytes(pr)
 selected_public=execute('dsmack_guest_io.public_inputs',guest/'runner-content/dsmack_guest_io/public_inputs.py',raw(guest/'runner-content/dsmack_guest_io/public_inputs.py','c33c79045a6f57a5d707c363bdff5116eacb3a8ea814682567fe90bb008ba81e'))
 need(selected_public.choose(tree/'public-inputs',tree/'manifests'/(selector+'.app-compose.json'),tree/'absent-private')==str(tree/'public-inputs'/(selector+'.envelope.json')),'actual public channel selection')
 need(not(tree/'envelopes').exists()and not(tree/'broker').exists(),'private channel refused')
 transport.start_overall_deadline(300);transport.build_workload_disk(None,str(tree),str(out/'workload.img'),1073741824)
 packed_public_sha=verify_packed_public_envelope(out/'workload.img',selector,pr)
 print(json.dumps({'schema':'dsmack-review-public-disk/1','selector':selector,'assignment_id':request['attempt_id'],'execution_attempt_id':a.execution_attempt_id,'manifest_sha256':sha(mr),'public_projection_sha256':sha(pr),'context_sha256':sha(canonical(context)),'workload_sha256':file_sha(out/'workload.img'),'workload_bytes':(out/'workload.img').stat().st_size,'oci_manifest_digest':IMAGE,'oci_config_digest':CONFIG,'oci_delivery':delivery,'public_envelope_channel':True,'packed_public_envelope_sha256':packed_public_sha,'credentials_read':False,'provider_calls':False,'native_vm_launched':False},sort_keys=True))
if __name__=='__main__':main()
