"""Public-only constructor. Caller independently selects reference/guest source."""
import argparse,base64,hashlib,json,sys
from pathlib import Path
SELECTOR='claude-broker-diagnostic-v1'
IMAGE='d91250b5d024b5b995de52e20eba57ba48f01e9562bec4562d1f88702d2d675c'
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def configure(reference,driver,cli_driver):
 m=json.loads(reference);c=json.loads(m['docker_compose_file']);services=c['services']
 if len(services)!=1 or next(iter(services.values()))['image'].split('@sha256:')[-1]!=IMAGE:raise ValueError('selected d912 reference required')
 if m['network']!={'mode':'nat','listen_ports':[]} or m['harness']['sha256']!='304aa87a76ebb13fd22d253ac157f14980ff2cdb23e6274f3b045571405e07dc':raise ValueError('reference transport/harness')
 service={'image':'127.0.0.1:5005/dsmack-bounty-generator-v1@sha256:'+IMAGE,'entrypoint':['/usr/bin/python3','-I','-B'],'command':['/workspace/inputs/driver','--expected-driver-sha256',sha(driver),'--expected-cli-driver-sha256',sha(cli_driver)],'read_only':True,'volumes':['driver:/workspace/inputs/driver:ro','cli-driver:/workspace/inputs/cli_driver:ro','state:/workspace/state:rw','artifacts:/workspace/artifacts:rw']}
 m['name']=SELECTOR;m['harness']['version']='broker-diagnostic-v1';m['docker_compose_file']=canonical({'services':{'diagnostic':service}}).decode()
 m['allowed_files']=[{'slot':'driver','target':'/workspace/inputs/driver','mode':'ro','audience':'workload','required':True,'max_bytes':65536}]
 m['allowed_files'].append({'slot':'cli-driver','target':'/workspace/inputs/cli_driver','mode':'ro','audience':'workload','required':True,'max_bytes':65536})
 m['limits']={'output_max_bytes':1048576,'timeout_s':120,'workspace_max_bytes':67108864}
 m['outputs']={'capture':['stdout','stderr'],'artifacts':[{'name':'broker-diagnostic','path':'/workspace/artifacts/broker-diagnostic.json'},{'name':'cli-diagnostic','path':'/workspace/artifacts/cli-diagnostic.json'}]}
 return m

def main():
 p=argparse.ArgumentParser()
 for n in ['reference-manifest','expected-reference-sha256','driver','expected-driver-sha256','cli-driver','expected-cli-driver-sha256','guest-source','out']:p.add_argument('--'+n,required=True)
 a=p.parse_args();reference=Path(a.reference_manifest).read_bytes()
 if sha(reference)!=a.expected_reference_sha256:raise ValueError('selected reference hash')
 driver=Path(a.driver).read_bytes()
 if len(driver)>65536 or sha(driver)!=a.expected_driver_sha256:raise ValueError('selected driver hash')
 cli_driver=Path(a.cli_driver).read_bytes()
 if len(cli_driver)>65536 or sha(cli_driver)!=a.expected_cli_driver_sha256:raise ValueError('selected CLI driver hash')
 m=configure(reference,driver,cli_driver)
 sys.path.insert(0,str(Path(a.guest_source)/'runner-content/lib'))
 from dsmack_compose_contract.manifest import validate_manifest_bytes
 from dsmack_compose_contract.runtime_inputs import compute_commitment
 mr=canonical(m);validate_manifest_bytes(mr)
 e={'runtime_input_version':4,'manifest_sha256':sha(mr),'files':[{'slot':'driver','content_base64':base64.b64encode(driver).decode()},{'slot':'cli-driver','content_base64':base64.b64encode(cli_driver).decode()}],'commitments':{'alg':'dsmack.task-commitment/3','scope':{'include':['files'],'file_slots':['cli-driver','driver']},'inputs_sha256':'0'*64}}
 e['commitments']['inputs_sha256']=compute_commitment(e,m);out=Path(a.out);out.mkdir(mode=0o700)
 for n,b in [('compose-manifest.json',mr),('public-file-projection.json',canonical(e))]:
  with(out/n).open('xb')as f:f.write(b)
  (out/n).chmod(0o600)
 print(json.dumps({'nonbounty_diagnostic':True,'manifest_sha256':sha(mr),'projection_sha256':sha(canonical(e)),'credentials_read':False,'vm_launched':False}))
if __name__=='__main__':main()
