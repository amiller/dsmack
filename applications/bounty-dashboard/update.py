#!/usr/bin/env python3
"""One persistent read-only collector/exporter and dashboard publisher. No wallet or chain writes."""
import argparse,fcntl,json,os,pathlib,subprocess,time,sys
import importlib.util
HERE=pathlib.Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("dashboard_publish",HERE/"publish.py");_publisher=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_publisher);normalize,send=_publisher.normalize,_publisher.send
def atomic(p,b):
 t=p.with_suffix('.tmp');t.write_bytes(b);t.chmod(0o600);os.replace(t,p)
def process_identity(pid):
 try:return pathlib.Path('/proc',str(pid),'stat').read_text().split(') ',1)[1].split()[19]
 except FileNotFoundError:return None
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,required=True);p.add_argument('--history-config',required=True);p.add_argument('--token-file',required=True);p.add_argument('--node',required=True);p.add_argument('--wait-for-pid',type=int);p.add_argument('--once',action='store_true');a=p.parse_args();r=a.root;r.mkdir(mode=0o700,parents=True,exist_ok=True)
 lock=(r/'updater.lock').open('a+b');fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
 if a.wait_for_pid:
  identity=process_identity(a.wait_for_pid)
  while identity is not None and process_identity(a.wait_for_pid)==identity:time.sleep(5)
 (r/'UPDATER-STARTED.json').write_text(json.dumps({'pid':os.getpid(),'started_at':time.time(),'readonly_chain':True})+'\n')
 while True:
  try:
   stage='collect'
   cmd=[sys.executable,'-I','-B',str(HERE/'chain/collect.py'),'--state-dir',str(r/'state'),'--out',str(r/'chain.json'),'--event-pages','100']
   c=subprocess.run(cmd,capture_output=True,timeout=240,pass_fds=(lock.fileno(),));atomic(r/'collector.stderr',c.stderr)
   if c.returncode:raise ValueError('collector stopped')
   stage='export'
   e=subprocess.run([a.node,'--no-warnings',str(HERE/'feeds/project.mjs'),a.history_config],capture_output=True,timeout=30);atomic(r/'export.stderr',e.stderr)
   if e.returncode:raise ValueError('history exporter stopped')
   feed=json.loads(e.stdout);atomic(r/'historical-feed.json',e.stdout)
   stage='publish'
   result=send(normalize(json.loads((r/'chain.json').read_text()),[feed]),pathlib.Path(a.token_file));atomic(r/'LAST-PUBLISH.json',json.dumps({**result,'published_at':time.time()}).encode())
  except Exception as ex:atomic(r/'UPDATE-ERROR.json',json.dumps({'type':type(ex).__name__,'stage':stage,'at':time.time()}).encode())
  if a.once:return
  time.sleep(120)
if __name__=='__main__':main()
