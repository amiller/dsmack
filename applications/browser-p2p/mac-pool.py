#!/usr/bin/env python3
"""Run a public quick tunnel for the lifetime of one attested Mac guest launch."""
import argparse,json,os,re,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'applications/compute-node'))
from pool import preflight,MacOccupied


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('state','runner','reference','peer','gateway','ca','relay','cloudflared','publisher-key'):
        p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--publisher-address',required=True);p.add_argument('--registry',required=True)
    p.add_argument('--index',default='https://pod.dstack.soc1024.com/private-agent/tunnels')
    a=p.parse_args();a.state.mkdir(mode=0o700,parents=True)
    while True:
        try:check=preflight(a.state,[]);break
        except MacOccupied:print('waiting for the other Mac lane',flush=True);time.sleep(10)
    (a.state/'preflight.json').write_text(json.dumps(check))
    stopping=False;children=[];logs=[];guest=None;published=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    def start(command,name):
        log=(a.state/name).open('w');logs.append(log)
        proc=subprocess.Popen([str(v) for v in command],stdout=log,stderr=subprocess.STDOUT);children.append(proc);return proc
    def wait_for(path,pattern,seconds):
        deadline=time.monotonic()+seconds
        while not stopping and time.monotonic()<deadline:
            for proc in children:
                if proc.poll() is not None:raise RuntimeError(f'child {proc.args[0]} exited {proc.returncode}; inspect logs')
            if path.exists():
                found=re.search(pattern,path.read_text(errors='replace'))
                if found:return found[1]
            time.sleep(.5)
        raise RuntimeError('readiness timeout: '+str(path))
    def publish(entries,label,chain=True):
        directory=a.state/label;directory.mkdir();path=directory/'entries.json';path.write_text(json.dumps(entries))
        command=[sys.executable,ROOT/'applications/browser-p2p/publish.py','publish' if chain else 'broker','--key',a.publisher_key,'--publisher-address',a.publisher_address,'--registry',a.registry,'--broker',a.index,'--entries',path,'--evidence',directory]
        subprocess.run([str(v) for v in command],check=True,timeout=480)
    try:
        start([a.relay,a.publisher_key.parent/'relay.key'],'relay.log')
        relay=wait_for(a.state/'relay.log',r'relay_peer=(12D3KooW\S+)',30)
        start([a.cloudflared,'tunnel','--no-autoupdate','--url','http://127.0.0.1:4019'],'tunnel.log')
        hostname=wait_for(a.state/'tunnel.log',r'https://([a-z0-9-]+\.trycloudflare\.com)',90)
        wait_for(a.state/'tunnel.log',r'(Registered tunnel connection)',90)
        locator=dict(url='wss://'+hostname+'/',relayPeer=relay,startedAt=int(time.time()))
        (a.state/'locator.json').write_text(json.dumps(locator,indent=2))
        print(json.dumps(locator),flush=True)
        subprocess.run([sys.executable,str(ROOT/'applications/browser-p2p/workload.py'),'--base',str(a.runner/'base'),'--reference',str(a.reference),'--peer',str(a.peer),'--gateway',str(a.gateway),'--ca',str(a.ca),'--hostname',hostname,'--relay-peer',relay,'--out',str(a.state/'workload')],check=True)
        run=a.state/'run';run.mkdir()
        (a.state/'workload/disk/workload.img').rename(run/'workload.img')
        import shutil
        shutil.copyfile(a.state/'workload/compose-manifest.json',run/'compose-manifest.json')
        start([sys.executable,ROOT/'applications/compute-node/connect-proxy.py','--listen','127.0.0.1','--port','18290','--model-host',hostname],'proxy.log')
        guest=start([sys.executable,ROOT/'applications/libp2p-attest/run-mac.py',a.runner,run],'guest-launch.log')
        peer=wait_for(run/'out/console-v3.log',r'peer [^\n]*/p2p-circuit/p2p/(12D3KooW[1-9A-HJ-NP-Za-km-z]{44})',180)
        locator['guestPeer']=peer
        (a.state/'locator.json').write_text(json.dumps(locator,indent=2))
        entries=[dict(url=locator['url'],relayPeer=relay,guestPeer=peer,expiresAt=int(time.time())+3300)]
        # Record intent before either publication: cleanup clears a partial success.
        published=True;publish(entries,'publish')
        refreshed=time.monotonic()
        while guest.poll() is None:
            if stopping:print('draining the owned guest before stopping its tunnel',flush=True)
            for proc in children:
                if proc is not guest and proc.poll() is not None:raise RuntimeError('relay/tunnel/proxy exited; inspect logs')
            if time.monotonic()-refreshed>60:
                entries[0]['expiresAt']=int(time.time())+3300
                publish(entries,'http-'+str(time.time_ns()),chain=False);refreshed=time.monotonic()
            time.sleep(2)
        if guest.returncode:raise RuntimeError('guest launcher failed; inspect guest-launch.log')
    finally:
        # Let run-mac.py close its VM and helper before stopping their transport.
        if guest and guest.poll() is None:
            try:guest.wait(timeout=660)
            except subprocess.TimeoutExpired:raise RuntimeError('guest still active; owned transport retained for inspection')
        try:
            if published:publish([],'retire')
        finally:
            for proc in reversed(children):
                if proc.poll() is None:proc.terminate()
            for proc in children:
                try:proc.wait(timeout=15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            for log in logs:log.close()
            (a.state/'stopped.json').write_text(json.dumps(dict(stoppedAt=int(time.time()),ownedChildrenStopped=all(p.poll() is not None for p in children),pids=[p.pid for p in children])))

if __name__=='__main__':main()
