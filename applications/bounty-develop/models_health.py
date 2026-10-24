#!/usr/bin/env python3
"""One explicit Mini-local OAuth models-route health observation; never refresh/model.

Fixed /v1/models route is permitted by the pinned sentinel /v1 allowlist. Diagnostic
only: profile success does not prove model entitlement or historical VM route.
No proxies (http.client), redirects, response bodies or private hashes emitted.
"""
import http.client,json,signal,ssl,time
from pathlib import Path
import hashlib,types
_dependency=Path(__file__).with_name('renew_private.py')
_raw=_dependency.read_bytes()
if hashlib.sha256(_raw).hexdigest()!='99f87297082c00bc6d827971c8ea169a75f7b32f8d8cd923a5605384b13ef94e':raise SystemExit('Renewal dependency refused')
_m=types.ModuleType('pinned_private_helpers');exec(compile(_raw,str(_dependency),'exec'),_m.__dict__)
regular,protected,load_validator,need=(_m.regular,_m.protected,_m.load_validator,_m.need)
HOST='api.anthropic.com';PATH='/v1/models';MAX=65536

def health(source,validator_source,ca='/etc/ssl/cert.pem',connection=None):
 protected(Path(source).parent);v=load_validator(validator_source);oauth=v.parse_subscription_document(regular(source,65536,True));ttl=int(oauth['expiresAt']/1000-time.time())
 conn=(connection or http.client.HTTPSConnection)(HOST,timeout=10,context=ssl.create_default_context(cafile=ca))
 status=None;category='transport_unknown';old=signal.getsignal(signal.SIGALRM);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'no ambient timer')
 def expired(*_):raise TimeoutError()
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,20)
 try:
  conn.request('GET',PATH,headers={'Authorization':'Bearer '+oauth['accessToken'],'User-Agent':'dsmack-private-health/1','Content-Type':'application/json','Cache-Control':'no-cache','anthropic-beta':'oauth-2025-04-20','anthropic-version':'2023-06-01'})
  response=conn.getresponse();status=response.status;raw=response.read(MAX+1)
  if len(raw)>MAX:category='response_bound'
  elif status==200:category='models_route_ok'
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
 return {'schema':'dsmack-private-models-health/1','http_status':status,'category':category,'remaining_lifetime_seconds':ttl,'credential_hashed':False,'response_exported':False,'refresh_performed':False,'model_calls':False}
if __name__=='__main__':
 import argparse,sys
 try:
  need(sys.flags.isolated==1,'isolated interpreter required');p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--validator-source',required=True);a=p.parse_args();print(json.dumps(health(a.source,a.validator_source)))
 except BaseException:raise SystemExit('Credential health refused')from None
