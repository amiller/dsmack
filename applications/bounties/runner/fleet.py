#!/usr/bin/env python3
"""One serial Mac poller for fixed operator-selected service registrations."""
import argparse,fcntl,json,os,re,subprocess,sys,time
from pathlib import Path
source=Path(__file__).with_name('client.py');c={'__name__':'fleet_client','__file__':str(source)};exec(compile(source.read_bytes(),str(source),'exec'),c)
p=c['_scope'];need=p['need'];canonical=p['canonical'];exclusive=p['exclusive']
def save(path,value):
    tmp=path.with_suffix('.tmp');fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb')as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
def log(path):
    if path.exists()and path.stat().st_size>1048576:os.replace(path,path.with_suffix(path.suffix+'.old'))
    return os.fdopen(os.open(path,os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o600),'ab')
def cycle(entry,root,progress):
    name=entry['name'];generation=progress.get(name,0);work=root/(name+str(generation))
    if not work.exists():work.mkdir(mode=0o700)
    config=work/'config.json'
    if not config.exists():
        cfg=c['state'](entry['config']);cfg['state_dir']=str(work);exclusive(config,canonical(cfg))
    intent=work/'fleet-child-active.json'
    # An interrupted child may have launched. Retain it for explicit reconciliation.
    need(not intent.exists(),'previous child outcome unknown; inspect retained state')
    exclusive(intent,canonical({'started_at':int(time.time())}))
    with log(work/'worker.stdout')as out,log(work/'worker.stderr')as err:
        child=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).with_name('node_worker.py')),'--config',str(config),'--registration',entry['registration'],'--wait-seconds','0'],stdout=out,stderr=err)
    need(child.returncode==0,'worker failed; inspect retained state before continuing')
    lease=work/'node-lease-result.json'
    if lease.exists():
        result=c['state'](lease);local=p['task_directory'](work,result['attempt_id']);cleanup=c['state'](local/'CLEANUP-COMPLETE.json')
        need(cleanup.get('native_quiescent')is True and cleanup.get('original21_preserved')is True,'completed cleanup required before another lease')
        progress[name]=generation+1;save(root/'progress.json',progress)
    intent.unlink()
def main():
    a=argparse.ArgumentParser();a.add_argument('--config',required=True);a.add_argument('--state',required=True);x=a.parse_args()
    entries=c['state'](x.config)['services'];need(1<=len(entries)<=8 and len({e['name']for e in entries})==len(entries),'fixed distinct services')
    need(all(re.fullmatch('[a-z][a-z0-9-]{0,12}',e['name'])for e in entries),'short service names')
    root=p['protected'](x.state,True);fd=os.open(root/'fleet.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    while True:
        progress=c['state'](root/'progress.json')if(root/'progress.json').exists()else{}
        for entry in entries:cycle(entry,root,progress)
        time.sleep(10)
if __name__=='__main__':main()
