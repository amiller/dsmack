"""Fixed claim handler for runner/worker.py's existing JSON job ABI.

The shared worker binding config selects a separate pinned bridge config.
No HTTP caller can select either the script/config, RPC or role key paths.
"""
import argparse,hashlib,json,pathlib,sys,types

def require(v,m):
 if not v:raise ValueError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def handle(request,binding,module,make_bridge=None):
 require(set(request)=={'action','input','job_dir','input_sha256'}and request['action']=='claim','claim job contract')
 require(hashlib.sha256(canonical(request['input'])).hexdigest()==request['input_sha256'],'claim input digest')
 root=pathlib.Path(binding['state_dir']).resolve(strict=True);job=pathlib.Path(request['job_dir']);require(job.is_absolute()and job==job.resolve(strict=True)and job.is_relative_to(root),'owned claim job path')
 require(job.stat().st_mode&0o077==0,'private claim job')
 desc=binding['claim_bridge']['config'];raw=module.secure_read(desc['path'],1048576,True);require(len(raw)==desc['bytes']and module.sha(raw)==desc['sha256'],'selected bridge config changed');c=module.parse(raw)
 bridge=make_bridge(c)if make_bridge else module.Bridge(c,module.RPC(c['rpc_url']),module.selected_validator(c))
 return {'public_result':bridge.process(request['input']),'artifacts':[]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--config-sha256',required=True);a=ap.parse_args();require(sys.flags.isolated,'isolated interpreter required')
 # Before loading the selected bridge module, require its descriptor from the
 # root-pinned shared binding; source is public and contains no signing scalars.
 raw=pathlib.Path(a.config).read_bytes();require(len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==a.config_sha256,'shared worker binding pin');binding=json.loads(raw);d=binding['claim_bridge']['script'];p=pathlib.Path(d['path']);source=p.read_bytes();require(len(source)==d['bytes']and hashlib.sha256(source).hexdigest()==d['sha256'],'selected bridge source pin');m=types.ModuleType('selected_arcade_claim_bridge');m.__file__=str(p);exec(compile(source,str(p),'exec'),m.__dict__)
 # Re-read through the bridge's no-follow/ownership/mode checks before actions.
 require(m.secure_read(a.config,1048576,True)==raw,'shared binding changed');request=m.parse(sys.stdin.buffer.read(1048577));require(len(canonical(request))<=1048576,'claim job input bound');print(canonical(handle(request,binding,m)).decode())
if __name__=='__main__':
 try:main()
 except Exception:
  print('Claim handler refused; preserve journal and reconcile before retry',file=sys.stderr);raise SystemExit(2)
