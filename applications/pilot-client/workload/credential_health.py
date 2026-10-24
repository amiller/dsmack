#!/usr/bin/env python3
"""One explicit Mini-local OAuth profile health observation; never refresh/model.

Fixed endpoint observed in local Claude Code2.1.308 implementation. Diagnostic
only: profile success does not prove model entitlement or historical VM route.
No proxies (http.client), redirects, response bodies or private hashes emitted.
"""
import http.client,json,signal,ssl,time
from pathlib import Path
import hashlib,types
import os,stat
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
def load_validator(path):
 b=regular(path,65536);need(hashlib.sha256(b).hexdigest()==VALIDATOR_SHA,'validator pin');m=types.ModuleType('pinned_validator');exec(compile(b,str(path),'exec'),m.__dict__);return m

HOST='api.anthropic.com';PATH='/api/oauth/profile';MAX=65536

def health(source,validator_source,ca='/etc/ssl/cert.pem',connection=None):
 protected(Path(source).parent);v=load_validator(validator_source);oauth=v.parse_subscription_document(regular(source,65536,True));ttl=int(oauth['expiresAt']/1000-time.time())
 conn=(connection or http.client.HTTPSConnection)(HOST,timeout=10,context=ssl.create_default_context(cafile=ca))
 status=None;category='transport_unknown';old=signal.getsignal(signal.SIGALRM);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'no ambient timer')
 def expired(*_):raise TimeoutError()
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,20)
 try:
  conn.request('GET',PATH,headers={'Authorization':'Bearer '+oauth['accessToken'],'User-Agent':'dsmack-private-health/1','Content-Type':'application/json','Cache-Control':'no-cache'})
  response=conn.getresponse();status=response.status;raw=response.read(MAX+1)
  if len(raw)>MAX:category='response_bound'
  elif status==200:category='profile_ok'
  elif status==401:category='authentication_refused'
  elif status==403:category='permission_refused'
  elif status==429:category='rate_limited'
  elif 300<=status<400:category='redirect_refused'
  elif 500<=status<=599:category='provider_server_error'
  else:category='other_http_status'
 except ssl.SSLError:category='tls_error'
 except TimeoutError:category='transport_timeout'
 except OSError:category='transport_error'
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old);conn.close()
 return {'schema':'dsmack-private-credential-health/1','http_status':status,'category':category,'remaining_lifetime_seconds':ttl,'credential_hashed':False,'response_exported':False,'refresh_performed':False,'model_calls':False}
if __name__=='__main__':
 import argparse,sys
 try:
  need(sys.flags.isolated==1,'isolated interpreter required');p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--validator-source',required=True);a=p.parse_args();print(json.dumps(health(a.source,a.validator_source)))
 except BaseException:raise SystemExit('Credential health refused')from None
