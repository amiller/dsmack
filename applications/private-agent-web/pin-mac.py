#!/usr/bin/env python3
"""Serve a recursive page pin and stable IPNS name for the Mac pool lifetime."""
import argparse,json,os,re,signal,subprocess,time
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ipfs','cloudflared','car','state'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.state.mkdir(parents=True,exist_ok=True,mode=0o700)
    env=dict(os.environ,IPFS_PATH=str(a.state/'repo'));stop=False;children=[];logs=[]
    def stopping(*_):
        nonlocal stop
        stop=True
    signal.signal(signal.SIGTERM,stopping);signal.signal(signal.SIGINT,stopping)
    def ipfs(*args):return subprocess.check_output([str(a.ipfs),*args],env=env,text=True,timeout=240).strip()
    def start(cmd,name):
        log=(a.state/name).open('w');logs.append(log)
        child=subprocess.Popen([str(x) for x in cmd],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT);children.append(child);return child
    if not (a.state/'repo/config').exists():ipfs('init','--profile=server')
    cfg=json.loads((a.state/'repo/config').read_bytes());name=ipfs('key','list','-l')
    if not any(line.strip().endswith(' friends-page') for line in name.splitlines()):ipfs('key','gen','--type=ed25519','friends-page')
    name=next(line.split()[0] for line in ipfs('key','list','-l').splitlines() if line.strip().endswith(' friends-page'))
    # Only the public key/name leaves this host. Kubo keeps the signing key in its repository.
    (a.state/'name.json').write_text(json.dumps({'name':name}))
    try:
        tunnel=start([a.cloudflared,'tunnel','--no-autoupdate','--url','http://127.0.0.1:4049'],'tunnel.log')
        deadline=time.monotonic()+100
        while True:
            match=re.search(r'https://([a-z0-9-]+\.trycloudflare\.com)',(a.state/'tunnel.log').read_text())
            if match:host=match[1];break
            if stop or tunnel.poll() is not None or time.monotonic()>deadline:raise RuntimeError('IPFS tunnel readiness failed')
            time.sleep(1)
        cfg['Addresses'].update(Swarm=['/ip4/127.0.0.1/tcp/4049/ws'],Announce=['/dns4/'+host+'/tcp/443/wss'],API='/ip4/127.0.0.1/tcp/15092',Gateway='/ip4/127.0.0.1/tcp/18092')
        cfg.setdefault('Swarm',{})['DisableNatPortMap']=True
        cfg['Datastore']['StorageMax']='1GB'
        (a.state/'repo/config').write_text(json.dumps(cfg))
        daemon=start([a.ipfs,'daemon','--migrate=true'],'daemon.log')
        deadline=time.monotonic()+100
        while 'Daemon is ready' not in (a.state/'daemon.log').read_text():
            if stop or daemon.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Kubo readiness failed')
            time.sleep(1)
        result=ipfs('dag','import',str(a.car));print(result,flush=True)
        root=json.loads(ipfs('dag','import','--enc=json',str(a.car)))['Root']['Cid']['/']
        ipfs('pin','add',root)
        result=ipfs('name','publish','--key=friends-page','--lifetime=168h','/ipfs/'+root);print(result,flush=True)
        record={'cid':root,'name':name,'provider':ipfs('id','-f=<id>'),'transport':'/dns4/'+host+'/tcp/443/wss','publishedAt':int(time.time()),'gateway':'https://'+name+'.ipns.dweb.link/'}
        (a.state/'published.json').write_text(json.dumps(record,indent=2));print(json.dumps(record),flush=True)
        while not stop:
            for child in children:
                if child.poll() is not None:raise RuntimeError('IPFS child exited: '+str(child.returncode))
            time.sleep(2)
    finally:
        for child in reversed(children):
            if child.poll() is None:child.terminate()
        for child in children:
            try:child.wait(timeout=20)
            except subprocess.TimeoutExpired:child.kill();child.wait()
        for log in logs:log.close()
        (a.state/'stopped.json').write_text(json.dumps({'stoppedAt':int(time.time()),'retainedRecursivePin':True}))

if __name__=='__main__':main()
