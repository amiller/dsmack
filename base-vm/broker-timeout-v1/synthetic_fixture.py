import ast,hashlib,http.client,http.server,json,pathlib,socket,ssl,threading,time,types
root=pathlib.Path('/input')
def source(name,expected):
 b=(root/name).read_bytes();assert hashlib.sha256(b).hexdigest()==expected;return b
base=types.ModuleType('original_sentinel');exec(compile(source('sentinel.py','c7e9e1d37253e05c1d756231aa7171808985a566366a9a646cb69b7807afba07'),'original-sentinel','exec'),base.__dict__)
b=source('sentinel_oauth.py','176107aed140e0986c0787c4779058a789f96d0e74dd51c09f844adb54a83bf5');tree=ast.parse(b);body=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='SubscriptionSentinel'];env={**base.__dict__,'OAUTH_BETA':'oauth-2025-04-20','time':time};exec(compile(ast.Module(body=body,type_ignores=[]),'original-subscription-class','exec'),env)
records=[]
class Dummy:
 def get_access_token_for_request(self):return 'DUMMY-NOT-VALID'
class Upstream(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def do_GET(self):
  if self.path.endswith('silent'):
   time.sleep(15)
  if self.path.endswith('oversize'):
   self.send_response(200);self.send_header('Content-Length',str(33554433));self.end_headers()
   try:
    for _ in range(512):self.wfile.write(b'x'*65536)
    self.wfile.write(b'x');self.wfile.flush()
   except OSError:pass
   return
  if self.path.endswith('error'):
   self.send_response(503);self.send_header('Content-Length','5');self.end_headers();self.wfile.write(b'error');return
  duration=1 if self.path.endswith(('short','silent'))else 55
  data=b'data: dummy\n\n';self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(duration*len(data)));self.end_headers()
  start=time.monotonic()
  for _ in range(duration):
   try:self.wfile.write(data);self.wfile.flush()
   except OSError:break
   time.sleep(1)
  records.append({'upstream_path':self.path,'elapsed':round(time.monotonic()-start,3)})
up=http.server.ThreadingHTTPServer(('127.0.0.1',0),Upstream);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/input/cert.pem','/input/key.pem');up.socket=ctx.wrap_socket(up.socket,server_side=True);threading.Thread(target=up.serve_forever,daemon=True).start()
closes=[];real=http.client.HTTPSConnection
class ObserveClose(real):
 def close(self):closes.append(time.monotonic());return super().close()
env['http']=types.SimpleNamespace(client=types.SimpleNamespace(HTTPSConnection=ObserveClose))
s=env['SubscriptionSentinel']('synthetic','dummy','https://localhost:'+str(up.server_port),'/input/cert.pem',Dummy());server=base.SentinelServer(('127.0.0.1',0),s);server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start()
results=[]
disconnect=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2);disconnect.request('GET','/dummy/v1/disconnect');time.sleep(0.1);disconnect.close()
for name in ('short','long','silent','oversize','error'):
 c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=60);start=time.monotonic();before=len(closes)
 try:
  c.request('GET','/dummy/v1/'+name);r=c.getresponse();headers=time.monotonic()-start;first=r.read(1);result={'case':name,'status':r.status,'first_response_seconds':round(headers,3),'first_byte_present':bool(first)};r.read()
 except Exception as e:result={'case':name,'error_class':type(e).__name__,'elapsed_seconds':round(time.monotonic()-start,3)}
 finally:c.close()
 result['upstream_close_callbacks_seconds']=[round(x-start,3)for x in closes[before:]];results.append(result)
time.sleep(6)
permits=[]
for _ in range(16):permits.append(server.request_gate.acquire(blocking=False))
for acquired in permits:
 if acquired:server.request_gate.release()
print(json.dumps({'schema':'dsmack-original-sentinel-synthetic-streaming/1','source_unchanged':True,'constants_unchanged':False,'selected_two_constant_delta':True,'synthetic_only':True,'provider_requests':False,'real_credentials':False,'instrumentation':'HTTPConnection subclass records close callbacks, delegates unchanged original close','limits':{'upstream':base.UPSTREAM_TOTAL_TIMEOUT_S,'handler':base.MAX_REQUEST_SECONDS},'results':results,'upstream':records,'all_16_permits_recovered':all(permits),'disconnect_case':'client closed immediately; permit recovery measured after upstream completion'},sort_keys=True),flush=True)
server.shutdown();up.shutdown()
