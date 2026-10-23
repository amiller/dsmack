#!/usr/bin/env python3
"""Offline exact-policy derivative; no actual base default, keys, RPC or Store."""
import argparse,copy,hashlib,json,os,re,stat,subprocess
from pathlib import Path
OLD_BASE='d9c169af135432e7e6c5309ac02f77f960254df8ce5b91cbd9a03c0b4af043b2'
PINS={'policy':'38a63897a22cf1885843d479622759acfeb67a21dd14f5be6d793f7869eb9ea7','first':'96619644fc67eedd2386aba34829104e228297c658632db27b639409aeebaddc','second':'414c424772cfa8357334e8d676b97f687ee2cda347a60d28daf99a8e5abb4a8c'}
SENTINEL='c7e9e1d37253e05c1d756231aa7171808985a566366a9a646cb69b7807afba07'
IDS=('board-search-opus48-transport-v2','board-search-opus48-transport-v2-repeat-2')
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(b):return hashlib.sha256(b).hexdigest()
def unique(pairs):
 d={}
 for k,v in pairs:need(k not in d,'duplicate JSON key');d[k]=v
 return d
def parse(b):
 def reject(_):raise ValueError('noninteger/nonfinite JSON number')
 return json.loads(b,object_pairs_hook=unique,parse_float=reject,parse_constant=reject)
def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):need(type(v)is str and re.fullmatch('[a-f0-9]{64}',v)and len(set(v))>1,'nonplaceholder SHA256');return v
def read(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=limit,'bounded ordinary public file');b=f.read(limit+1);t=os.fstat(f.fileno());need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns)and len(b)==s.st_size,'stable public bytes');return b

def construct(base_bytes,expected_base_sha,originals):
 digest(expected_base_sha);need(sha(base_bytes)==expected_base_sha,'externally selected base descriptor hash')
 base=parse(base_bytes);need(canonical(base)==base_bytes,'canonical base descriptor')
 need(set(base)=={'schema','original_base_sha256','base_vm_os_image_hash','source_derivation_sha256','qualification_review_sha256','sentinel_source_sha256'},'closed qualified-base descriptor')
 need(base['schema']=='dsmack-qualified-broker-timeout-base/1'and base['original_base_sha256']==OLD_BASE and base['sentinel_source_sha256']==SENTINEL,'selected two-constant source derivation')
 for k in set(base)-{'schema'}:digest(base[k])
 new=base['base_vm_os_image_hash'];need(new!=OLD_BASE,'new base required')
 need(set(originals)==set(PINS),'three original inputs')
 docs={}
 for k,b in originals.items():need(sha(b)==PINS[k],'original '+k+' pin');docs[k]=parse(b);need(canonical(docs[k])==b,'original canonical '+k)
 p=copy.deepcopy(docs['policy']);need(p['images']['base_vm_os_image_hash']==OLD_BASE,'original policy base');p['images']['base_vm_os_image_hash']=new;p['policy_id']=IDS[0]
 p['public_binding']['base_identity']='each outer admission independently pins the selected transport-v2 base identity and held-fd boot closure; receipt checked against expected base'
 p['transport_compatibility']={'schema':'dsmack-broker-buffered-timeout-compatibility/1','qualified_base_descriptor_sha256':expected_base_sha,'sentinel_source_sha256':SENTINEL,'upstream_watchdog_seconds':210,'client_handler_watchdog_seconds':220,'upstream_socket_idle_seconds':10,'response_buffer_bytes':33554432,'request_bytes_max':8388608,'concurrent_requests_max':16,'streaming_forwarding':False,'hard_abort_guarantee':False,'guest_execution_budget_seconds':600,'residual':'Watchdog close does not guarantee interruption of an in-progress upstream response read or immediate handler/permit release; VM teardown remains final boundary. No streaming-progress or historical-GEN-causality claim.'}
 policy=canonical(p);terms=[]
 for k,ident in zip(('first','second'),IDS):
  t=copy.deepcopy(docs[k]);need(t['image_sha256']==OLD_BASE and t['checker_sha256']==PINS['policy'],'original terms bindings');t['id']=ident;t['image_sha256']=new;t['checker_sha256']=sha(policy);terms.append(canonical(t))
 return {'acceptance-policy.json':policy,'first-task-terms.json':terms[0],'second-task-terms.json':terms[1]}

NODE_PROGRAM="const fs=require('node:fs');const v=JSON.parse(fs.readFileSync(0,'utf8'));const c=x=>Array.isArray(x)?x.map(c):x!==null&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,c(x[k])])):x;process.stdout.write(JSON.stringify(c(v)));"
def node_parity(node,outputs):
 need(Path(node).is_absolute(),'explicit absolute Node runtime')
 for raw in outputs.values():
  v=subprocess.run([node,'-e',NODE_PROGRAM],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':'/usr/bin:/bin'},check=False);need(v.returncode==0 and v.stdout==raw,'Node canonical UTF8 parity')
def emit(out,name,raw):
 fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
 ap=argparse.ArgumentParser()
 for k in ('base-descriptor','expected-base-descriptor-sha256','policy','first-terms','second-terms','node','out'):ap.add_argument('--'+k,required=True)
 a=ap.parse_args();b=read(a.base_descriptor,65536);outputs=construct(b,a.expected_base_descriptor_sha256,{'policy':read(a.policy,1048576),'first':read(a.first_terms,65536),'second':read(a.second_terms,65536)});node_parity(a.node,outputs)
 out=Path(a.out);need(out.is_absolute(),'absolute fresh output');out.mkdir(mode=0o700);emit(out,'selected-qualified-base.json',b)
 for n,raw in outputs.items():emit(out,n,raw)
 result={'schema':'dsmack-transport-v2-policy-preparation/1','base_descriptor_sha256':sha(b),'original_pins':PINS,'files':{n:{'bytes':len(raw),'sha256':sha(raw)}for n,raw in outputs.items()},'node_canonical_parity':True,'funds_moved':False,'store_changed':False,'provider_calls':False,'qualification_authority':'External root selects actual qualified descriptor and its exact hash; this tool does not qualify a base from metadata.'};emit(out,'RESULT.json',canonical(result));fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit('Transport-v2 policy preparation refused; retain partial output, no overwrite.')from None
