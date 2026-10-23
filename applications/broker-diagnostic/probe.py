"""Non-bounty, value-free probe through the already admitted sentinel only."""
import argparse,hashlib,http.client,json,os,re,socket,time
from pathlib import Path
from urllib.parse import urlsplit
SCHEMA='dsmack-broker-diagnostic/1'
def endpoint(value):
 r=urlsplit(value)
 if not (r.scheme=='http' and r.hostname=='172.17.0.1' and r.port==5100 and r.netloc=='172.17.0.1:5100' and re.fullmatch('/[A-Za-z0-9_-]{1,128}',r.path) and not r.query and not r.fragment):raise ValueError('endpoint refused')
 return r

def classify(exc):
 if isinstance(exc,(socket.timeout,TimeoutError)):return 'timeout'
 if isinstance(exc,ConnectionRefusedError):return 'connection-refused'
 if isinstance(exc,socket.gaierror):return 'name-resolution-failed'
 return 'transport-error'
def probe(value,*,connect=socket.create_connection,connection=http.client.HTTPConnection,clock=time.monotonic):
 r=endpoint(value);rows=[];start=clock()
 t=clock()
 try:
  s=connect((r.hostname,r.port),timeout=5);s.close();rows.append({'step':'broker-tcp','result':'connected','milliseconds':round((clock()-t)*1000)})
 except (OSError,TimeoutError) as e:
  rows.append({'step':'broker-tcp','result':classify(e),'milliseconds':round((clock()-t)*1000)})
  return {'schema':SCHEMA,'scope':'nonbounty-diagnostic','steps':rows,'acceptance_evaluated':False,'provider_message_requested':False}
 t=clock();c=connection(r.hostname,r.port,timeout=10)
 try:
  # The path capability is run-local; never print/store the endpoint or headers.
  c.request('GET',r.path+'/v1/models',headers={'Authorization':'Bearer '+r.path[1:],'anthropic-version':'2023-06-01','anthropic-beta':'oauth-2025-04-20','Content-Type':'application/json','Cache-Control':'no-store','User-Agent':'dsmack-broker-diagnostic/1'})
  response=c.getresponse();status=response.status
  rows.append({'step':'broker-models','result':'http-response','http_status':status,'status_class':status//100,'milliseconds':round((clock()-t)*1000)})
  # Discard body without reading or retaining it. No redirects or proxy support.
 except (OSError,TimeoutError,http.client.HTTPException) as e:
  rows.append({'step':'broker-models','result':classify(e),'milliseconds':round((clock()-t)*1000)})
 finally:c.close()
 t=clock();c=connection(r.hostname,r.port,timeout=10)
 try:
  body=json.dumps({'model':'claude-opus-4-8','max_tokens':8,'messages':[{'role':'user','content':'Reply OK.'}],'stream':False},separators=(',',':')).encode()
  c.request('POST',r.path+'/v1/messages',body=body,headers={'Authorization':'Bearer '+r.path[1:],'anthropic-version':'2023-06-01','anthropic-beta':'oauth-2025-04-20','Content-Type':'application/json','Cache-Control':'no-store','User-Agent':'dsmack-broker-diagnostic/1'})
  response=c.getresponse();status=response.status
  rows.append({'step':'broker-message','result':'http-response','http_status':status,'status_class':status//100,'milliseconds':round((clock()-t)*1000)})
 except (OSError,TimeoutError,http.client.HTTPException) as e:
  rows.append({'step':'broker-message','result':classify(e),'milliseconds':round((clock()-t)*1000)})
 finally:c.close()
 return {'schema':SCHEMA,'scope':'nonbounty-diagnostic','steps':rows,'elapsed_milliseconds':round((clock()-start)*1000),'acceptance_evaluated':False,'provider_message_requested':True}

def run_cli(expected):
 if not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('CLI driver pin')
 fd=os.open('/workspace/inputs/cli_driver',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb')as f:body=f.read(65537)
 if len(body)>65536 or hashlib.sha256(body).hexdigest()!=expected:raise ValueError('CLI driver source refused')
 ns={'__name__':'selected_cli_diagnostic','__file__':'/workspace/inputs/cli_driver'}
 exec(compile(body,ns['__file__'],'exec'),ns)
 ns['main']()

def main():
 p=argparse.ArgumentParser();p.add_argument('--expected-driver-sha256',required=True);p.add_argument('--expected-cli-driver-sha256',required=True);a=p.parse_args()
 if not re.fullmatch('[a-f0-9]{64}',a.expected_driver_sha256) or hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=a.expected_driver_sha256:raise ValueError('driver pin refused')
 # CLI runs first because the unchanged selected helper requires empty outputs.
 run_cli(a.expected_cli_driver_sha256)
 value=probe(os.environ.get('DSMACK_SENTINEL_ENDPOINT',''))
 out=Path('/workspace/artifacts/broker-diagnostic.json');b=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
 if len(b)>4096:raise ValueError('report bound')
 fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b)
 print(json.dumps({'diagnostic_report_written':True,'acceptance_evaluated':False}))
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit('Diagnostic refused; private diagnostics withheld')from None
