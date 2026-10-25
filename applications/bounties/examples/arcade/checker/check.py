#!/usr/bin/env python3
"""Protected Arcade checker. Candidate bytes execute only in Chromium."""
import argparse, hashlib, http.server, json, os, pathlib, signal, stat, subprocess, threading, time
BASE_COMMIT='5c76d40e77db1f4864dabd4b9398d02589cff330'
CHECKER_INPUT_COMMIT='82323836a672b799ac8f9f74265498f97438cd02'
ALLOWED=frozenset('apps/board/'+n for n in ('index.html','logic.js','ui.js'))
TESTS=['board-add-save','search-control','substring-case-trim','blank-and-counts','view-only-export','filtered-move','reload-view-reset']
DEFAULT_TESTS=TESTS
PROFILES={
 'board-undo-testnet-1':('board',['undo-controls','history-api','history-limit','edit-delete-move','redo-branch','import-clears','shortcuts-reload']),
 'puzzle-deadlock-testnet-1':('puzzle',['deadlock-api','level-starts','corner-indices','non-dead-cases','corner-warning','undo-restart','second-level-warning']),
 'routes-segments-testnet-1':('routes',['segments-api','gap-distance','gap-elevation','default-stats','samples-unchanged','upload-segments','sample-switch']),
}
TASK_SLUG='board-search-testnet-1'
APP='board'
def select_profile():
 global TASK_SLUG,APP,ALLOWED,TESTS
 TASK_SLUG=json.loads((HERE/'base-files.json').read_bytes()).get('task_slug','board-search-testnet-1')
 if TASK_SLUG=='board-search-testnet-1':
  APP='board';TESTS=DEFAULT_TESTS;ALLOWED=frozenset('apps/board/'+n for n in ('index.html','logic.js','ui.js'));return
 if TASK_SLUG not in PROFILES:raise Invalid('task_profile')
 APP,TESTS=PROFILES[TASK_SLUG];ALLOWED=frozenset('apps/'+APP+'/'+n for n in ('index.html','logic.js','ui.js'))
HERE=pathlib.Path(__file__).resolve().parent
canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode()
sha=lambda b:hashlib.sha256(b).hexdigest()
class Invalid(ValueError):pass

def tree(root):
 root=pathlib.Path(root)
 if not root.is_absolute() or root.is_symlink() or not root.is_dir():raise Invalid('candidate_directory')
 rows={};total=0
 for parent,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:
   p=pathlib.Path(parent)/name;s=p.lstat();rel=p.relative_to(root).as_posix()
   if p.is_symlink()or '..'in pathlib.PurePosixPath(rel).parts:raise Invalid('source_path')
   if stat.S_ISDIR(s.st_mode):continue
   if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1 or s.st_size>1048576:raise Invalid('source_file')
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   with os.fdopen(fd,'rb')as f:
    before=os.fstat(f.fileno());b=f.read(1048577);after=os.fstat(f.fileno())
   if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns)or len(b)!=s.st_size:raise Invalid('source_changed')
   total+=len(b)
   if total>8388608 or len(rows)>=128:raise Invalid('source_bounds')
   rows[rel]=b
 return rows

def validate(base,candidate):
 expected=json.loads((HERE/'base-files.json').read_bytes())
 if {p:sha(b)for p,b in base.items()}!=expected['files']:raise Invalid('frozen_base_mismatch')
 if set(candidate)!=set(base):raise Invalid('candidate_file_set')
 changed=sorted(p for p in base if base[p]!=candidate[p])
 if any(p not in ALLOWED for p in changed):raise Invalid('candidate_scope')
 return changed,sha(canonical({p:sha(b)for p,b in sorted(candidate.items())}))

class Server(http.server.ThreadingHTTPServer):daemon_threads=True

def serve(files):
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):
   resources=set(ALLOWED)|{p for p in files if p=='apps/puzzle/levels.json'and APP=='puzzle' or p.startswith('apps/routes/samples/')and p.endswith('.gpx')and APP=='routes'}
   paths={'/apps/'+APP+'/':'apps/'+APP+'/index.html',**{'/'+p:p for p in resources}}
   # No URL decoding, traversal, directory listing, uploads or candidate-controlled server.
   name=paths.get(self.path)
   if name is None:self.send_error(404);return
   b=files[name];self.send_response(200)
   self.send_header('Content-Type','text/html; charset=utf-8'if name.endswith('.html')else'application/json'if name.endswith('.json')else'application/gpx+xml'if name.endswith('.gpx')else'text/javascript; charset=utf-8')
   self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store')
   connect="'none'"if TASK_SLUG=='board-search-testnet-1'else"'self'"
   self.send_header('Content-Security-Policy',f"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data: blob:; connect-src {connect}; object-src 'none'; base-uri 'none'; frame-src 'none'")
   self.end_headers();self.wfile.write(b)
 server=Server(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();return server

def classify(observed, code):
 if type(observed)is not dict or set(observed)!={'outcome','tests'}:raise RuntimeError('browser_protocol')
 tests=observed['tests']
 if type(tests)is not list or len(tests)>len(TESTS):raise RuntimeError('browser_tests')
 if any(type(x)is not dict or set(x)!={'id','status'}for x in tests):raise RuntimeError('browser_test_contract')
 ids=[x['id']for x in tests]
 if ids!=TESTS[:len(ids)]or any(x['status']not in('passed','assertion_failed','infrastructure_failure')for x in tests):raise RuntimeError('browser_test_contract')
 success=code==0 and observed['outcome']=='passed'and ids==TESTS and all(x['status']=='passed'for x in tests)
 functional=code==3 and observed['outcome']=='functional_failure'and tests and tests[-1]['status']=='assertion_failed'and all(x['status']=='passed'for x in tests[:-1])
 return ('passed'if success else'functional_failure'if functional else'infrastructure_failure'),tests

def bounded_browser(cmd,env,deadline=100):
 child=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=HERE,start_new_session=True)
 try:
  stdout,stderr=child.communicate(timeout=deadline)
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.communicate(timeout=3)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=3)
  raise RuntimeError('checker_deadline')
 return child.returncode,stdout,stderr

def save(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())

def main():
 p=argparse.ArgumentParser();p.add_argument('--base-dir',required=True);p.add_argument('--candidate-dir',required=True);p.add_argument('--out',required=True);a=p.parse_args()
 out=pathlib.Path(a.out)
 if not out.is_absolute()or out==pathlib.Path(a.candidate_dir)or pathlib.Path(a.candidate_dir)in out.parents:raise Invalid('output_inside_candidate')
 select_profile()
 out.mkdir(mode=0o700,parents=False,exist_ok=True)
 if out.is_symlink()or not out.is_dir()or any(out.iterdir()):raise Invalid('fresh_output_required')
 started=time.monotonic();result={'schema':'dsmack-arcade-checker-result/1','task_slug':TASK_SLUG,'base_commit':BASE_COMMIT,'checker_input_commit':CHECKER_INPUT_COMMIT,'outcome':'infrastructure_failure','passed':False,'tests':[],'candidate_tree_sha256':None,'changed_files':[],'artifacts':[]};server=None
 try:
  base=tree(a.base_dir);candidate=tree(a.candidate_dir)
  if out==pathlib.Path(a.candidate_dir)or pathlib.Path(a.candidate_dir)in out.parents:raise Invalid('output_inside_candidate')
  changed,digest=validate(base,candidate);result.update(candidate_tree_sha256=digest,changed_files=changed)
  server=serve(candidate)
  env={'PATH':'/usr/bin:/bin','HOME':str(out),'PLAYWRIGHT_BROWSERS_PATH':os.environ.get('PLAYWRIGHT_BROWSERS_PATH','/ms-playwright')}
  cmd=['/usr/bin/node',str(HERE/'browser.mjs'),'http://127.0.0.1:'+str(server.server_port),str(out)]+([TASK_SLUG]if TASK_SLUG!='board-search-testnet-1'else[])
  code,stdout,stderr=bounded_browser(cmd,env)
  if len(stdout)>65536 or len(stderr)>65536:raise RuntimeError('browser_output_bounds')
  if code!=0:print(stderr.decode('utf-8','replace')[:4096],file=__import__('sys').stderr)
  outcome,tests=classify(json.loads(stdout),code)
  result.update(outcome=outcome,passed=outcome=='passed',tests=tests)
 except Invalid as e:result.update(outcome='invalid_candidate',error_category=str(e))
 except Exception:result.update(outcome='infrastructure_failure',error_category='checker_execution')
 finally:
  if server:server.shutdown();server.server_close()
 for name in ('final.png','trace.zip','video.webm'):
  f=out/name
  if f.is_file()and not f.is_symlink()and 0<f.stat().st_size<=67108864:
   b=f.read_bytes();magic={'final.png':b'\x89PNG\r\n\x1a\n','trace.zip':b'PK','video.webm':b'\x1aE\xdf\xa3'}[name]
   if b.startswith(magic):result['artifacts'].append({'name':name,'bytes':len(b),'sha256':sha(b)})
 if result['passed']and len(result['artifacts'])!=3:result.update(outcome='infrastructure_failure',passed=False,error_category='media_export')
 result['elapsed_ms']=round((time.monotonic()-started)*1000);save(out/'checker-result.json',result)
 print(json.dumps({'outcome':result['outcome'],'passed':result['passed']}));return {'passed':0,'functional_failure':3,'invalid_candidate':2,'infrastructure_failure':4}[result['outcome']]
if __name__=='__main__':
 try:raise SystemExit(main())
 except Invalid:raise SystemExit(2)
