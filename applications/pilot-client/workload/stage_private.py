#!/usr/bin/env python3
"""JIT explicit credential stdin to original PRIVATE VDE; no provider or VM.

Never hash/print private values or image bytes. All partial private residue is
retained under the new owned0700 output namespace on refusal. Independent task
admission, funded claim, no concurrent refresh and subsequent launch selection
remain caller requirements. Python memory erasure is not guaranteed.
"""
import argparse,contextlib,io,json,os,signal,stat,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from transport_loader import load,raw
from build_review import canonical,sha,need,read
def credential_contract():
 return {'required':True,'via':'runtime-input-broker','adapter':{'accepted_fields':['claudeAiOauth'],'profile':'claude-subscription/1','provider_route':'https://api.anthropic.com','source':'explicit-caller-stdin-or-file'}}
MIN_TTL_SECONDS=1200

def unique(rows):
 d={}
 for k,v in rows:need(k not in d,'duplicate member');d[k]=v
 return d

def credential(raw_doc,now,validator):
 obj=validator.parse_credential_source(raw_doc)
 expiry=obj['expiresAt']/1000 if 'expiresAt' in obj else None
 need(expiry is None or expiry-now>=MIN_TTL_SECONDS,'credential remaining lifetime too short')
 return validator.canonical_env_value(obj),expiry

def bounded_stdin(stream,seconds=15):
 previous=signal.getsignal(signal.SIGALRM)
 need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'no preexisting input timer')
 def expired(*_):raise TimeoutError('credential input deadline')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,seconds)
 try:return stream.read(65537)
 finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

def private_parent(path):
 s=path.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'owned0700 private parent required')

def write(path,body):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb',closefd=False)as f:f.write(body);f.flush();os.fsync(fd)
 finally:os.close(fd)

def selected_transport(a):
 if a.transport_backend=='linux-memfd-v1':
  need(sys.platform=='linux'and hasattr(os,'memfd_create'),'Linux memfd backend unavailable')
  need(a.portable_module is None and a.temporary_parent is None,'portable arguments on Linux backend')
  return load(a.transport_module)
 need(a.transport_backend=='darwin-owned-tempfile-v1'and sys.platform=='darwin','explicit Darwin backend required')
 need(a.portable_module is not None and a.temporary_parent is not None,'selected portable source and temporary parent required')
 path=Path(a.portable_module);body=raw(path);m=types.ModuleType('selected_portable_private_transport');m.__file__=str(path)
 exec(compile(body,str(path),'exec'),m.__dict__)
 return m.load_portable(a.transport_module,a.temporary_parent)

class ValueFreeArguments(argparse.ArgumentParser):
 def error(self,message):raise ValueError('argument contract refused')

def main():
 ap=ValueFreeArguments(description=__doc__)
 for n in ('preparation','expected-manifest-sha256','expected-projection-sha256','guest-source','transport-module','private-parent','out-name'):ap.add_argument('--'+n,required=True)
 ap.add_argument('--transport-backend',choices=('linux-memfd-v1','darwin-owned-tempfile-v1'),default='linux-memfd-v1');ap.add_argument('--portable-module');ap.add_argument('--temporary-parent')
 a=ap.parse_args();parent=Path(a.private_parent);need(parent.is_absolute(),'absolute private parent');private_parent(parent)
 need(a.out_name and len(a.out_name)<=80 and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-'for c in a.out_name),'private namespace name')
 prep=Path(a.preparation);manifest=read(prep/'compose-manifest.json',1048576);projection=read(prep/'public-file-projection.json',33554432)
 need(sha(manifest)==a.expected_manifest_sha256 and sha(projection)==a.expected_projection_sha256,'independent selected public pins')
 m=json.loads(manifest,object_pairs_hook=unique);e=json.loads(projection,object_pairs_hook=unique)
 need(m['credentials']==credential_contract()and e['manifest_sha256']==sha(manifest),'selected credential contract')
 need(set(e)=={'runtime_input_version','manifest_sha256','files','commitments'},'public projection must exclude private values')
 sys.path.insert(0,str(Path(a.guest_source)/'runner-content/lib'))
 from dsmack_compose_contract.runtime_inputs import validate_runtime_inputs_bytes,compute_commitment
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 validate_manifest_bytes(manifest);selector=m['name'];need(compute_commitment(e,m)==e['commitments']['inputs_sha256'],'selected public commitment')
 vpath=Path(__file__).resolve().parent/'reference/claude_subscription_document.py';validator=types.ModuleType('selected_subscription_validator');exec(compile(raw(vpath),str(vpath),'exec'),validator.__dict__)
 transport=selected_transport(a)
 # All public/source/namespace checks happen BEFORE explicit credential read.
 doc=bounded_stdin(sys.stdin.buffer);need(len(doc)<=65536,'credential byte cap');value,expiry=credential(doc,time.time(),validator)
 e['env']={'CLAUDE_SUBSCRIPTION_OAUTH':value};full=canonical(e);validate_runtime_inputs_bytes(manifest,full)
 out=parent/a.out_name;out.mkdir(mode=0o700);stage=out/'input-tree';stage.mkdir(mode=0o700)
 for d in ('envelopes','broker','broker/'+selector):(stage/d).mkdir(mode=0o700)
 write(stage/'envelopes'/(selector+'.envelope.json'),full)
 write(stage/'broker'/selector/'credential',value.encode())
 cfg={'listen_port':5100,'workload_host':'172.17.0.1','provider_route':'https://api.anthropic.com','ca_bundle':'/etc/ssl/certs/ca-certificates.crt','auth_mode':'claude-subscription'}
 write(stage/'broker'/selector/'broker-config.json',canonical(cfg))
 transport.start_overall_deadline(300)
 with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
  need(transport.build_private_disk(None,str(stage),str(out/'private-input.img'),1073741824),'private disk missing')
 need(expiry is None or expiry-time.time()>=MIN_TTL_SECONDS,'credential lifetime consumed during staging')
 # Metadata only: NO private content/image digest, no raw exception/log output.
 print(json.dumps({'schema':'dsmack-jit-private-input-stage/1','transport_backend':a.transport_backend,'kernel_write_seals':a.transport_backend=='linux-memfd-v1','private_input_present':True,'complete_private_envelope':True,'manifest_sha256':a.expected_manifest_sha256,'public_projection_sha256':a.expected_projection_sha256,'remaining_lifetime_seconds':int(expiry-time.time()) if expiry is not None else None,'private_content_hashed_for_report':False,'provider_calls':False,'vm_launched':False,'private_residue_retained':True},sort_keys=True))
if __name__=='__main__':
 try:main()
 except SystemExit:raise
 except BaseException as error:
  print('DSMACK_PRIVATE_STAGE_REFUSED '+type(error).__name__,file=sys.stderr);sys.exit(2)
