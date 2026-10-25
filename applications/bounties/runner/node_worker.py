#!/usr/bin/env python3
"""Optional Mac worker: one normal public node lease, same client/proof rules."""
import argparse,contextlib,fcntl,hashlib,json,os,secrets,sys,time
from pathlib import Path
s=Path(__file__).with_name('client.py');c={'__name__':'arcade_client','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),c)
p=c['_scope'];need=p['need'];read=p['read'];doc=p['document'];canonical=p['canonical'];exclusive=p['exclusive']

@contextlib.contextmanager
def execution_lock(config):
    parent=p['protected'](Path(config['install_root']).parent,True)
    fd=os.open(parent/'.node-execution.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:os.close(fd)

def run_worker(cfg,reg,api,root,wait_seconds):
    # One durable lease/run per invocation. A subsequent run requires a fresh
    # state directory/config only after CLEANUP-COMPLETE has been inspected.
    intent=root/'node-lease-request.json'
    if intent.exists():request=c['state'](intent);need(request['key_id']==reg['key_id'],'node identity changed')
    else:request={'request_id':secrets.token_hex(32),'key_id':reg['key_id'],'capability':secrets.token_urlsafe(32)};exclusive(intent,canonical(request))
    resultpath=root/'node-lease-result.json';deadline=time.monotonic()+wait_seconds
    if resultpath.exists():lease=c['state'](resultpath)
    else:
        while True:
            lease=api.request('POST','/api/nodes/lease',request,reg['node_capability'])
            if lease:exclusive(resultpath,canonical(lease));break
            if time.monotonic()>=deadline:print(json.dumps({'queued_task_available':False,'vm_launched':False}));return
            time.sleep(5)
    packet=lease['execution'];attempt=lease['attempt_id'];need(packet['attempt_id']==attempt and packet['key_id']==reg['key_id'],'node task binding')
    local=p['task_directory'](root,attempt)
    if (local/'CLEANUP-COMPLETE.json').exists():print(read(local/'CLEANUP-COMPLETE.json').decode());return
    if not local.exists():task=p['materialize'](cfg,packet,reg['key_id'],root,api.fetch)
    else:task=local/'task.json';need(doc(read(local/'execution-packet.json'))==packet,'saved execution changed')
    native=packet['native_execution_id'];plan=local/('attempt-'+native+'.control')/'plan.json'
    if not plan.exists():need(p['coordinator'](cfg,'prepare',task,local,native)==0,'native preparation refused')
    journal=plan.parent/'launch-requested.json'
    if not journal.exists():
        need(p['coordinator'](cfg,'check',task,local,native)==0,'native check refused')
        need(p['coordinator'](cfg,'run',task,local,native)==0,'execution uncertain; retain originals, do not relaunch')
    else:
        # Do not repeat even if an earlier HTTP/reporting operation failed.
        p['coordinator'](cfg,'resume',task,local,native)
    submitted=local/'EVIDENCE-SUBMITTED.json'
    if not submitted.exists():
        r=c['upload'](api,attempt,lease['capability'],local/('attempt-'+native),hashlib.sha256((attempt+'evidence').encode()).hexdigest());exclusive(submitted,canonical(r))
    deadline=time.monotonic()+900
    while True:
        status=api.request('GET','/api/attempts/'+attempt)
        if status.get('verdict'):break
        need(time.monotonic()<deadline,'verification pending; no next task/cleanup until full proof');time.sleep(5)
    cleanup_path=Path(__file__).with_name('cleanup.py');ns={'__name__':'arcade_cleanup','__file__':str(cleanup_path)};exec(compile(cleanup_path.read_bytes(),str(cleanup_path),'exec'),ns)
    result=ns['retire'](cfg,packet,local,status['verdict']);print(json.dumps({'attempt_id':attempt,'same_public_verification':True,'cleanup':result}))

def main():
    a=argparse.ArgumentParser();a.add_argument('--config',required=True);a.add_argument('--registration',required=True);a.add_argument('--allow-loopback',action='store_true');a.add_argument('--wait-seconds',type=int,default=600);x=a.parse_args();need(0<=x.wait_seconds<=3600,'bounded wait')
    cfg=c['state'](x.config);reg=c['state'](x.registration);api=c['API'](cfg['api_url'],x.allow_loopback);root=p['protected'](cfg['state_dir'],True)
    with execution_lock(cfg):run_worker(cfg,reg,api,root,x.wait_seconds)

if __name__=='__main__':
    try:main()
    except Exception:
        print('Node worker stopped; preserve state/originals and reconcile, never blind retry',file=sys.stderr);raise SystemExit(2)
