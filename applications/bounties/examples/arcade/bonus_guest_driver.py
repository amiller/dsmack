#!/usr/bin/env python3
"""Supervisor for deterministic bonus checks; exports valid negative outcomes."""
import base64,hashlib,json,os,subprocess,sys
from pathlib import Path
canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def need(v,m):
 if not v:raise ValueError(m)
def tree(raw,dest):
 v=json.loads(raw);need(type(v)is dict and 0<len(v)<=128,'tree membership');total=0;digests={}
 dest.mkdir(mode=0o700)
 for name,encoded in sorted(v.items()):
  p=Path(name);need(not p.is_absolute()and all(x not in ('','.','..')for x in p.parts)and '\\'not in name and name==p.as_posix(),'tree path')
  b=base64.b64decode(encoded,validate=True);total+=len(b);need(len(b)<=1048576 and total<=8388608,'tree bound');out=dest/p;out.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  with out.open('xb')as f:f.write(b)
  out.chmod(0o400);digests[name]=hashlib.sha256(b).hexdigest()
 return hashlib.sha256(canonical(digests)).hexdigest()
def run(inputs,state,art):
 need(not any(state.iterdir())and not any(art.iterdir()),'fresh state/output required')
 request=json.loads((inputs/'request.json').read_bytes());profile=json.loads((inputs/'base-files.json').read_bytes())['task_slug']
 need(profile in ('board-undo-testnet-1','puzzle-deadlock-testnet-1','routes-segments-testnet-1','flight-wind-testnet-1','flight-replay-testnet-1','routes-time-testnet-1'),'new deterministic task profile required')
 base=state/'base';candidate=state/'candidate'
 base_hash=tree((inputs/'base.json').read_bytes(),base);candidate_hash=tree((inputs/'candidate.json').read_bytes(),candidate)
 need(base_hash==request['base_tree_sha256']and candidate_hash==request['candidate_tree_sha256'],'input tree binding')
 checks={};codes={'passed':0,'functional_failure':3,'infrastructure_failure':4}
 for role,source in (('baseline',base),('candidate',candidate)):
  out=state/(role+'-outputs');out.mkdir(mode=0o700)
  proc=subprocess.run(['/usr/bin/python3','-I','-B',str(inputs/'check.py'),'--base-dir',str(base),'--candidate-dir',str(source),'--out',str(out)],env={'HOME':str(state),'PATH':'/usr/bin:/bin','PLAYWRIGHT_BROWSERS_PATH':'/ms-playwright'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
  need(len(proc.stdout)<=65536 and len(proc.stderr)<=65536,'checker output bound')
  result=json.loads((out/'checker-result.json').read_bytes());checks[role]=result
  need(result['schema']=='dsmack-arcade-checker-result/1'and result['task_slug']==profile,'typed checker identity')
  need(result['outcome']in codes and proc.returncode==codes[result['outcome']]and type(result['passed'])is bool and result['passed']==(result['outcome']=='passed'),'typed checker execution')
  need(result['candidate_tree_sha256']==(base_hash if role=='baseline'else candidate_hash),'checker input binding')
  need(type(result['tests'])is list and len(result['tests'])<=7 and all(t['status']in ('passed','assertion_failed','infrastructure_failure')for t in result['tests']),'checker test protocol')
  if result['outcome']=='passed':need(len(result['tests'])==7 and all(t['status']=='passed'for t in result['tests']),'complete checker success')
  if result['outcome']=='functional_failure':need(any(t['status']=='assertion_failed'for t in result['tests']),'functional assertion required')
  need(len(result['artifacts'])==3 and {x['name']for x in result['artifacts']}=={'final.png','trace.zip','video.webm'},'complete media')
  for d in result['artifacts']:
   b=(out/d['name']).read_bytes();need(len(b)==d['bytes']and hashlib.sha256(b).hexdigest()==d['sha256'],'media digest')
  for name in ('checker-result.json','final.png','trace.zip','video.webm'):
   with (art/(role+'-'+name)).open('xb')as exported:exported.write((out/name).read_bytes())
 # Successful execution means the protected checker ran, not that the patch passed.
 # The external factory recomputes acceptance from these authenticated outcomes.
 print(json.dumps({'baseline':checks['baseline']['outcome'],'candidate':checks['candidate']['outcome'],'native_outcome':'completed','candidate_tree_sha256':candidate_hash}))

def main():run(Path('/workspace/inputs'),Path('/workspace/state'),Path('/workspace/artifacts'))
if __name__=='__main__':
 try:main()
 except Exception:
  print('Protected checker protocol or infrastructure export failed',file=sys.stderr);raise SystemExit(4)
