"""Public-only constructor. Caller independently selects reference/guest source."""
import argparse,base64,hashlib,json,sys
from pathlib import Path
SELECTOR='claude-broker-diagnostic-v1'
IMAGE='d91250b5d024b5b995de52e20eba57ba48f01e9562bec4562d1f88702d2d675c'
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def configure(reference,driver,base,spec,snapshot):
 m=json.loads(reference);c=json.loads(m['docker_compose_file']);services=c['services']
 if len(services)!=1 or next(iter(services.values()))['image'].split('@sha256:')[-1]!=IMAGE:raise ValueError('selected d912 reference required')
 if m['network']!={'mode':'nat','listen_ports':[]} or m['harness']['sha256']!='304aa87a76ebb13fd22d253ac157f14980ff2cdb23e6274f3b045571405e07dc':raise ValueError('reference transport/harness')
 files=[('driver','/workspace/inputs/driver',driver),('base','/workspace/inputs/base.json',base),('spec','/workspace/inputs/spec.txt',spec)]
 service={'image':'127.0.0.1:5005/dsmack-bounty-generator-v1@sha256:'+IMAGE,'entrypoint':['/usr/bin/python3','-I','-B'],'command':['/workspace/inputs/driver','--public','/workspace/inputs','--flat-public','--snapshot-sha256',snapshot],'read_only':True,'volumes':[slot+':'+target+':ro' for slot,target,_ in files]+['state:/workspace/state:rw','artifacts:/workspace/artifacts:rw']}
 m['name']=SELECTOR;m['harness']['version']='generation-reliability-v1';m['docker_compose_file']=canonical({'services':{'diagnostic':service}}).decode()
 m['allowed_files']=[{'slot':slot,'target':target,'mode':'ro','audience':'workload','required':True,'max_bytes':max(65536,len(raw))} for slot,target,raw in files]
 m['limits']={'output_max_bytes':1048576,'timeout_s':550,'workspace_max_bytes':67108864}
 m['outputs']={'capture':['stdout','stderr'],'artifacts':[{'name':'generation-reliability','path':'/workspace/artifacts/generation-reliability.json'}]}
 return m

def main():
 p=argparse.ArgumentParser()
 for n in ['reference-manifest','expected-reference-sha256','driver','expected-driver-sha256','base','expected-base-sha256','spec','expected-spec-sha256','snapshot-sha256','guest-source','out']:p.add_argument('--'+n,required=True)
 a=p.parse_args();reference=Path(a.reference_manifest).read_bytes()
 if sha(reference)!=a.expected_reference_sha256:raise ValueError('selected reference hash')
 files=[]
 for name in ['driver','base','spec']:
  raw=Path(getattr(a,name)).read_bytes()
  if len(raw)>1048576 or sha(raw)!=getattr(a,'expected_'+name+'_sha256'):raise ValueError('selected '+name+' hash/limit')
  files.append(raw)
 driver,base,spec=files
 snapshot={'schema':'dsmack-bounty-generator-input/1','base_tree_sha256':'ca3ff7c4e70d33a481e672079ac381037f3940b8102f09d7c9e1d3b8ce9ab553','files':[{'name':name,'size':len(raw),'sha256':sha(raw)} for name,raw in [('base.json',base),('spec.txt',spec)]]}
 if sha(canonical(snapshot))!=a.snapshot_sha256:raise ValueError('held snapshot digest')
 m=configure(reference,driver,base,spec,a.snapshot_sha256)
 sys.path.insert(0,str(Path(a.guest_source)/'runner-content/lib'))
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import compute_commitment
 mr=canonical(m);validate_manifest_bytes(mr)
 e={'runtime_input_version':4,'manifest_sha256':sha(mr),'files':[{'slot':slot,'content_base64':base64.b64encode(raw).decode()} for slot,raw in zip(['driver','base','spec'],files)],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':['base','driver','spec']},'inputs_sha256':'0'*64}}
 e['commitments']['inputs_sha256']=compute_commitment(e,m);out=Path(a.out);out.mkdir(mode=0o700)
 for n,b in [('compose-manifest.json',mr),('public-file-projection.json',canonical(e))]:
  with(out/n).open('xb')as f:f.write(b)
  (out/n).chmod(0o600)
 print(json.dumps({'nonbounty_diagnostic':True,'manifest_sha256':sha(mr),'projection_sha256':sha(canonical(e)),'credentials_read':False,'vm_launched':False}))
if __name__=='__main__':main()
