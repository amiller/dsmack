#!/usr/bin/env python3
"""Zed-only heavy PUBLIC develop disk preparation; no credentials/VM/provider.

Copies the selected f62b OCI into this disk; never relies on Zed's registry.
Source imports are operator-selected trusted inputs in a stable namespace.
The original qualified transport and OCI helpers are loaded from exact raw
source, not cached bytecode. Real task admission remains external authority.
"""
import argparse,base64,hashlib,json,os,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from prepare import read,need,canonical,sha,SELECTOR,IMAGE
from transport_loader import load,execute,raw
CONFIG='sha256:e450ec3d48ab0c3604ef7a36874e4ddc1e7244c8a8ec74391e0ab964f8020e0b'
EXTERNAL={'closure.py':'8ed11fbb5b64e313463d2f24c527a570364a32675140cd8fadd00cca9888b54f','oci_publish.py':'d68fca5d394c3a934cfb3b66485534cd9051c67a10266be8f61a83879940b676','make_guest_inputs.py':'69a2e7c310a91f3b327d9ef859a941b84a500c9c3ac664be4d8d5f9e37a17537'}
def file_sha(path):
 h=hashlib.sha256()
 with open(path,'rb')as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def execution_context(projection,execution_attempt_id,selector=SELECTOR):
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
 manifest=json.loads(mr);projection=json.loads(pr);need(manifest['name']==SELECTOR and projection['manifest_sha256']==sha(mr),'selected develop manifest')
 request,context=execution_context(projection,a.execution_attempt_id)
 guest=Path(a.guest_source);sys.path.insert(0,str(guest/'runner-content/lib'))
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import compute_commitment
 validate_manifest_bytes(mr);need(compute_commitment(projection,manifest)==projection['commitments']['inputs_sha256'],'selected public commitment')
 transport=load(a.transport_module);package=sys.modules['dsmack_guest_io']
 for n in ('closure','oci_publish'):
  path=guest/'runner-content/dsmack_guest_io'/(n+'.py');setattr(package,n,execute('dsmack_guest_io.'+n,path,raw(path,EXTERNAL[n+'.py'])))
 path=guest/'build/make_guest_inputs.py';gi=execute('selected_original_guest_input_builder',path,raw(path,EXTERNAL[path.name]))
 out.mkdir(mode=0o700);tree=out/'public-tree';tree.mkdir(mode=0o700)
 for n in ('manifests','admission','base-bundle','commitments','closure-context'):(tree/n).mkdir()
 (tree/'manifests'/(SELECTOR+'.app-compose.json')).write_bytes(mr)
 base=manifest['base_vm'];art=Path(a.artifacts)
 for n,field in [('Image','kernel_sha256'),('initramfs.cpio.gz','initrd_sha256'),('rootfs.squashfs.verity','rootfs_sha256'),('metadata.json','metadata_sha256')]:
  need(not(art/n).is_symlink()and (art/n).is_file()and file_sha(art/n)==base[field],'selected base artifact identity');shutil.copyfile(art/n,tree/'base-bundle'/n);need(file_sha(tree/'base-bundle'/n)==base[field],'copied base artifact identity')
 checksum=read(art/'sha256sum.txt',65536);need(sha(checksum)==a.expected_checksum_sha256,'selected checksum manifest');(tree/'base-bundle/sha256sum.txt').write_bytes(checksum)
 (tree/'admission/base-admission.json').write_bytes(canonical({'admission_version':1,'allowed_os_image_hashes':[base['os_image_hash']]}))
 gi.emit_commitment_declaration(str(tree),SELECTOR,projection,sha(mr))
 need(request['run_role']=='develop'and request['candidate']is None,'develop request')
 (tree/'closure-context/context.json').write_bytes(canonical(context));(tree/'WORKLOAD').write_text(SELECTOR+'\n')
 delivery=gi.stage_oci_layout(str(tree),a.oci_layout,repo_name='dsmack-bounty-develop-v1');need(delivery['content_digest_preserved']==IMAGE,'actual develop OCI on disk')
 services=json.loads(manifest['docker_compose_file'])['services'];need(len(services)==1 and next(iter(services.values()))['image']==delivery['refs']['dsmack-bounty-develop-v1'],'manifest consumes staged cold-loopback OCI')
 blob=tree/'oci-layout/blobs/sha256'/IMAGE.split(':')[1];oci_manifest=json.loads(blob.read_bytes());need(oci_manifest['config']['digest']==CONFIG,'actual develop config on disk')
 # No public envelope channel. Files-only commitment declaration is measured;
 # the complete envelope and broker values are solely private VDE.
 need(not(tree/'public-inputs').exists()and not(tree/'envelopes').exists()and not(tree/'broker').exists(),'private/public channel collision')
 transport.start_overall_deadline(300);transport.build_workload_disk(None,str(tree),str(out/'workload.img'),1073741824)
 print(json.dumps({'schema':'dsmack-develop-public-disk/1','selector':SELECTOR,'assignment_id':request['attempt_id'],'execution_attempt_id':a.execution_attempt_id,'manifest_sha256':sha(mr),'public_projection_sha256':sha(pr),'context_sha256':sha(canonical(context)),'workload_sha256':file_sha(out/'workload.img'),'workload_bytes':(out/'workload.img').stat().st_size,'oci_manifest_digest':IMAGE,'oci_config_digest':CONFIG,'oci_delivery':delivery,'public_envelope_channel':False,'credentials_read':False,'provider_calls':False,'native_vm_launched':False},sort_keys=True))
if __name__=='__main__':main()
