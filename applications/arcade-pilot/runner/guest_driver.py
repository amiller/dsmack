#!/usr/bin/env python3
"""Measured deterministic checker supervisor; candidate code runs only in Chromium."""
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
def main():
 inputs=Path('/workspace/inputs');state=Path('/workspace/state');art=Path('/workspace/artifacts');need(not any(state.iterdir())and not any(art.iterdir()),'fresh state/output required')
 request=json.loads((inputs/'request.json').read_bytes());base=state/'base';candidate=state/'candidate'
 base_hash=tree((inputs/'base.json').read_bytes(),base);candidate_hash=tree((inputs/'candidate.json').read_bytes(),candidate)
 need(base_hash==request['base_tree_sha256']and candidate_hash==request['candidate_tree_sha256'],'input tree binding')
 checks={}
 for role,source,expected in (('baseline',base,3),('candidate',candidate,0)):
  out=art/role;out.mkdir(mode=0o700)
  proc=subprocess.run(['/usr/bin/python3','-I','-B','/checker/check.py','--base-dir',str(base),'--candidate-dir',str(source),'--out',str(out)],env={'HOME':str(state),'PATH':'/usr/bin:/bin','PLAYWRIGHT_BROWSERS_PATH':'/ms-playwright'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
  need(len(proc.stdout)<=65536 and len(proc.stderr)<=65536,'checker output bound')
  result=json.loads((out/'checker-result.json').read_bytes());checks[role]=result
  need(proc.returncode==expected and result['schema']=='dsmack-arcade-checker-result/1','typed checker execution')
  need(result['candidate_tree_sha256']==(base_hash if role=='baseline'else candidate_hash),'checker input binding')
  need(result['outcome']==('functional_failure'if role=='baseline'else'passed')and result['passed']==(role=='candidate'),'typed checker outcome')
  need(any(x['status']=='assertion_failed'for x in result['tests'])if role=='baseline'else len(result['tests'])==7 and all(x['status']=='passed'for x in result['tests']),'checker assertion coverage')
  need({x['name']for x in result['artifacts']}=={'final.png','trace.zip','video.webm'},'complete media')
  for d in result['artifacts']:
   b=(out/d['name']).read_bytes();need(len(b)==d['bytes']and hashlib.sha256(b).hexdigest()==d['sha256'],'media digest')
 # No worker/candidate supplied success flag is consulted.
 print(json.dumps({'baseline':'functional_failure','candidate':'passed','native_outcome':'completed','candidate_tree_sha256':candidate_hash}))
if __name__=='__main__':
 try:main()
 except Exception:
  print('Protected checker refused or encountered infrastructure failure',file=sys.stderr);raise SystemExit(4)
