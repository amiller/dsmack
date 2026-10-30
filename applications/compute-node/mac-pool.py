#!/usr/bin/env python3
"""Own a Mac quick tunnel, capped relay and CONNECT helper for the warm pool lifetime."""
import argparse,json,signal,subprocess,sys,time,re,socket,ssl,http.client,base64,hashlib,os,ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
from pool import preflight,MacOccupied

ROOT=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('runner','workload','state','relay','relay-key','cloudflared','publisher-key'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--broker',required=True);p.add_argument('--index',required=True)
    p.add_argument('--publication-rpc',default='https://base-sepolia-rpc.publicnode.com')
    p.add_argument('--registry',required=True);p.add_argument('--publisher-address',required=True)
    a=p.parse_args();a.state.mkdir(parents=True,mode=0o700)
    manifest=json.loads((a.workload/'compose-manifest.json').read_bytes())
    node=json.loads(manifest['docker_compose_file'])['services']['node']
    expected_peer=node['command'][1].rsplit('/',1)[1]
    seconds=int(node['command'][2]);admit=int(node['environment']['ADMIT_SECONDS'])
    while True:
        try:preflight(a.state,[]);break
        except MacOccupied:print('waiting for the active Mac lane',flush=True);time.sleep(10)
    stopping=False;children=[];logs=[];pool=None;published=False;failure=None
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    def start(command,name):
        log=(a.state/name).open('w');logs.append(log)
        proc=subprocess.Popen([str(x) for x in command],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
        children.append(proc);return proc
    def ready(path,pattern,seconds):
        deadline=time.monotonic()+seconds
        while not stopping and time.monotonic()<deadline:
            for proc in children:
                if proc.poll() is not None:raise RuntimeError('child exited; inspect '+str(path))
            if path.exists():
                m=re.search(pattern,path.read_text(errors='replace'))
                if m:return m[1]
            time.sleep(.5)
        raise RuntimeError('readiness timeout: '+str(path))
    def resolve(host):
        # dig uses the configured DNS server directly, avoiding mDNSResponder's
        # stale NXDOMAIN cache for newly-created quick-tunnel names.
        answer=subprocess.check_output(['dig','+time=3','+tries=1','+short',host,'A'],text=True,timeout=5)
        addresses=[ipaddress.IPv4Address(line) for line in answer.splitlines() if re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',line)]
        if not addresses or not addresses[0].is_global:raise ValueError('no public IPv4 DNS answer for '+host)
        return str(addresses[0])
    def public_ready(host):
        path=a.state/'tunnel-readiness.jsonl'
        for attempt in range(1,25):
            try:
                address=resolve(host)
                key=base64.b64encode(os.urandom(16)).decode()
                with socket.create_connection((address,443),timeout=5) as raw:
                    with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as connection:
                        connection.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\n\r\n').encode())
                        response=http.client.HTTPResponse(connection);response.begin()
                        expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                        if response.status!=101 or response.getheader('Sec-WebSocket-Accept')!=expected:raise ValueError('public WebSocket upgrade HTTP '+str(response.status))
                result={'attempt':attempt,'host':host,'address':address,'status':'ready'}
            except (OSError,http.client.HTTPException,ValueError,subprocess.SubprocessError) as error:result={'attempt':attempt,'host':host,'error':str(error)}
            with path.open('a') as log:log.write(json.dumps(result)+'\n')
            print(json.dumps(result),flush=True)
            if result.get('status')=='ready':return address
            if stopping:raise RuntimeError('stopped during public tunnel readiness')
            time.sleep(5)
        raise RuntimeError('public tunnel DNS/TLS/WebSocket readiness failed; inspect tunnel-readiness.jsonl')
    def publish(entries,chain):
        out=a.state/('publication-'+str(time.time_ns()));out.mkdir();path=out/'entries.json';path.write_text(json.dumps(entries))
        cmd=[sys.executable,ROOT/'applications/browser-p2p/publish.py','publish' if chain else 'broker','--key',a.publisher_key,'--publisher-address',a.publisher_address,'--registry',a.registry,'--broker',a.index,'--entries',path,'--evidence',out]
        if chain:cmd+=['--rpc',a.publication_rpc]
        subprocess.run([str(x) for x in cmd],check=True,timeout=480)
    try:
        with urlopen(a.broker.rstrip('/')+'/sandbox/transport',timeout=30) as response:broker_peer=json.load(response)['peer_id']
        start([a.relay,a.relay_key,a.broker.rstrip('/')+'/sandbox/p2p',broker_peer],'relay.log')
        relay=ready(a.state/'relay.log',r'relay_peer=(12D3KooW\S+)',30)
        if relay!=expected_peer:raise ValueError('relay key does not match the measured compose')
        start([a.cloudflared,'tunnel','--no-autoupdate','--url','http://127.0.0.1:4019'],'tunnel.log')
        host=ready(a.state/'tunnel.log',r'https://([a-z0-9-]+\.trycloudflare\.com)',90)
        ready(a.state/'tunnel.log',r'(Registered tunnel connection)',90)
        tunnel_address=public_ready(host)
        broker_host=urlsplit(a.broker).hostname;broker_address=resolve(broker_host)
        start([sys.executable,ROOT/'applications/compute-node/connect-proxy.py','--listen','127.0.0.1','--port','18484','--allow-host',host,'--allow-host',urlsplit(a.broker).hostname,'--connection-seconds','960','--resolve',host+'='+tunnel_address,'--resolve',broker_host+'='+broker_address],'proxy.log')
        hint=dict(url='wss://'+host+'/',relayPeer=relay,expiresAt=int(time.time())+3300)
        (a.state/'locator.json').write_text(json.dumps(hint,indent=2))
        published=True;publish([hint],True);last_http=last_chain=time.monotonic()
        pool=start([sys.executable,ROOT/'applications/compute-node/pool.py','--runner',a.runner,'--workload',a.workload,'--state',a.state/'guests','--repo',ROOT,'--broker',a.broker,'--seconds',str(seconds),'--drain-seconds',str(seconds-admit),'--replace-after',str(seconds//2+30),'--readiness-timeout','90'],'pool.log')
        draining=False
        while pool.poll() is None:
            for proc in children:
                if proc is not pool and proc.poll() is not None:
                    stopping=True;failure='relay/tunnel/proxy exited; inspect logs'
            if stopping and not draining:
                pool.send_signal(signal.SIGTERM);draining=True;print('draining warm guests',flush=True)
            now=time.monotonic()
            if now-last_http>=60:
                hint['expiresAt']=int(time.time())+3300
                chain=now-last_chain>=1200;publish([hint],chain);last_http=now
                if chain:last_chain=now
            time.sleep(2)
        if pool.returncode:raise RuntimeError('warm pool failed; inspect pool.log')
        if failure:raise RuntimeError(failure)
    finally:
        if pool and pool.poll() is None:
            pool.send_signal(signal.SIGTERM)
            try:pool.wait(timeout=1000)
            except subprocess.TimeoutExpired:raise RuntimeError('warm guests still active; owned transport retained')
        try:
            if published:publish([],True)
        finally:
            for proc in reversed(children):
                if proc.poll() is None:proc.terminate()
            for proc in children:
                try:proc.wait(timeout=15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            for log in logs:log.close()
            (a.state/'stopped.json').write_text(json.dumps(dict(stoppedAt=int(time.time()),ownedChildrenStopped=all(c.poll() is not None for c in children),pids=[c.pid for c in children])))

if __name__=='__main__':main()
