#!/usr/bin/env python3
"""Mini-only, explicitly selected one-shot credential renewal. No model/VM.

Call only after all subscription clients are quiescent. A durable intent prevents
blind retry when refresh-token rotation may have occurred. Input is preserved;
output is a new protected document, never printed or hashed.
"""
import ast,hashlib,http.client,json,os,ssl,stat,threading,time,types
from pathlib import Path
OAUTH_SHA='176107aed140e0986c0787c4779058a789f96d0e74dd51c09f844adb54a83bf5'
VALIDATOR_SHA='11f4e0fa320c741c2324bf21c0892a133c608d56b7e2b0e76e47c72556d12487'

def need(v,m):
 if not v:raise ValueError(m)
def regular(path,limit,private=False):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=limit,'file shape')
  if private:need(s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o600,'private file mode')
  b=f.read(limit+1);need(len(b)==s.st_size and len(b)<=limit,'file bound');return b

def protected(path):
 for parent in (path,*path.parents):
  s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid in (0,os.getuid())and not(s.st_mode&0o022),'protected directory chain')
 s=path.lstat();need(s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'owned0700 output')
def write(path,b):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def load_refresh(path):
 b=regular(path,131072);need(hashlib.sha256(b).hexdigest()==OAUTH_SHA,'original OAuth source pin')
 tree=ast.parse(b);selected=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='SubscriptionCredential'];need(len(selected)==1,'original refresh class')
 env={'json':json,'threading':threading,'time':time,'ssl':ssl,'http':__import__('http'),'SentinelError':RuntimeError,'FALLBACK_CLIENT_ID':'9d1c250a-e61b-44d9-88ed-5944d1962f5e','TOKEN_PATH':'/v1/oauth/token','OAUTH_BETA':'oauth-2025-04-20','REFRESH_CONNECT_TIMEOUT_S':10,'REFRESH_TOTAL_TIMEOUT_S':25,'MAX_REFRESH_RESPONSE_BYTES':65536,'REFRESH_WINDOW_SECONDS':300}
 exec(compile(ast.Module(body=selected,type_ignores=[]),str(path),'exec'),env);return env['SubscriptionCredential']
def load_validator(path):
 b=regular(path,65536);need(hashlib.sha256(b).hexdigest()==VALIDATOR_SHA,'validator pin');m=types.ModuleType('pinned_validator');exec(compile(b,str(path),'exec'),m.__dict__);return m

def renew(source,out,oauth_source,validator_source,ca_bundle):
 out=Path(out);protected(out);protected(Path(source).parent)
 need(not any(out.iterdir()),'fresh renewal output directory')
 # Authenticate executable source BEFORE reading the private document.
 cls=load_refresh(oauth_source);v=load_validator(validator_source)
 oauth=v.parse_subscription_document(regular(source,65536,True))
 write(out/'REFRESH-STARTED.json',b'{"schema":"dsmack-private-refresh-intent/1","do_not_retry_blindly":true}')
 c=cls(oauth,'https://api.anthropic.com',str(ca_bundle));c.refresh()
 doc=v.canonical_env_value(c._oauth).encode();parsed=v.parse_subscription_document(doc)
 # Preserve any validated rotated credential even if it cannot admit a run.
 write(out/'credential.json',doc)
 ttl=int(parsed['expiresAt']/1000-time.time())
 if ttl<1200:
  write(out/'REFRESH-LAUNCH-INADMISSIBLE.json',json.dumps({'schema':'dsmack-private-refresh-inadmissible/1','remaining_lifetime_seconds':ttl,'private_content_hashed':False}).encode())
 need(ttl>=1200,'renewed TTL below importer threshold')
 write(out/'REFRESH-COMPLETE.json',json.dumps({'schema':'dsmack-private-refresh-complete/1','remaining_lifetime_seconds':int(parsed['expiresAt']/1000-time.time()),'private_content_hashed':False,'model_calls':False}).encode())
 return {'complete':True,'remaining_lifetime_seconds':int(parsed['expiresAt']/1000-time.time()),'model_calls':False,'private_content_hashed':False}
if __name__=='__main__':
 import argparse,sys
 try:
  need(sys.flags.isolated==1,'isolated interpreter required');ap=argparse.ArgumentParser();ap.add_argument('--source',required=True);ap.add_argument('--out',required=True);ap.add_argument('--oauth-source',required=True);ap.add_argument('--validator-source',required=True);ap.add_argument('--ca-bundle',default='/etc/ssl/cert.pem');a=ap.parse_args();print(json.dumps(renew(a.source,a.out,a.oauth_source,a.validator_source,a.ca_bundle)))
 except BaseException:raise SystemExit('Credential renewal refused; retain intent and do not retry blindly')from None
