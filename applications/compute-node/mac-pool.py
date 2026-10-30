#!/usr/bin/env python3
"""Own a Mac quick tunnel, capped relay and CONNECT helper for the warm pool lifetime."""
import argparse,json,signal,subprocess,sys,time,re,socket,ssl,http.client,base64,hashlib,os,ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from pool import preflight,MacOccupied,hardware,operator_config,measured_size

ROOT=Path(__file__).resolve().parents[2]


def republish(publish,hint,chain):
    try:
        publish([hint],chain)
        return True
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
        print(json.dumps(dict(event='periodic-publication-failed',error=type(error).__name__,
                              chain=chain,retrySeconds=60)),flush=True)
        return False


def guest_entries(snapshot, hint, now=None):
    """Read locally observed guest identities, retaining their fixed admission expiry."""
    now = int(time.time()) if now is None else now
    entries = {}
    for slot in snapshot.get('slots', []):
        registration = slot.get('attestation')
        if not registration:
            continue
        expiry = min(registration['admit_until'], registration['payments']['runExpires'])
        if expiry > now:
            peer = registration['relay_peer']
            entries[peer] = dict(url=hint['url'], relayPeer=hint['relayPeer'],
                                 guestPeer=peer, expiresAt=expiry)
    return [entries[peer] for peer in sorted(entries)]


def publish_directory(publish, entries, previous, pending=False):
    if entries == previous and not pending:
        return previous
    try:
        publish(entries, True)
        return entries
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(json.dumps(dict(event='guest-directory-publication-failed',
                              error=type(error).__name__, retrySeconds=60)), flush=True)
        return previous


def publish_chain(entries, pending_path, prepare, run):
    """Reconcile one saved attempt before allocating any later transaction."""
    if pending_path.exists():
        out = Path(pending_path.read_text())
        previous = json.loads((out/'entries.json').read_text())
        if previous == entries or (out/'publish-transaction.json').exists():
            run(out)
            pending_path.unlink()
            if previous == entries:
                return
        else:
            pending_path.unlink()
    out = prepare(entries)
    temporary = pending_path.with_suffix('.tmp')
    temporary.write_text(str(out.resolve()))
    temporary.replace(pending_path)
    run(out)
    pending_path.unlink()


def discover_transport(broker, stopped=lambda: False, budget_seconds=60, retry_seconds=2):
    """Ride out broker promotion without restarting the owned Mac launcher."""
    started = time.monotonic()
    deadline = started + budget_seconds
    attempt = 0
    while not stopped():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempt += 1
        status = None
        try:
            with urlopen(broker.rstrip('/') + '/sandbox/transport', timeout=min(5, remaining)) as response:
                peer = json.load(response)['peer_id']
            if not isinstance(peer, str) or not re.fullmatch(r'12D3KooW[1-9A-HJ-NP-Za-km-z]{44}', peer):
                raise ValueError('broker transport returned an invalid Ed25519 peer ID')
            if stopped():
                break
            return peer
        except HTTPError as error:
            status = error.code
            error.close()
            if status not in (408, 429) and not 500 <= status <= 599:
                raise RuntimeError('broker transport discovery HTTP ' + str(status)) from None
            failure = type(error).__name__
        except (URLError, OSError, http.client.HTTPException) as error:
            failure = type(error).__name__
        remaining = deadline - time.monotonic()
        if stopped() or remaining <= 0:
            break
        delay = min(retry_seconds, remaining)
        print(json.dumps(dict(event='broker-transport-retry', attempt=attempt, error=failure,
                              status=status, elapsedSeconds=round(time.monotonic()-started, 3),
                              retrySeconds=delay)), flush=True)
        time.sleep(delay)
    if stopped():
        raise RuntimeError('stopped during broker transport discovery')
    raise RuntimeError('broker transport discovery unavailable after ' + str(budget_seconds) + ' seconds')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('runner','workload','state','relay','relay-key','cloudflared','publisher-key'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--pool-version',required=True,help='source commit used by this staged pool')
    p.add_argument('--operator',type=Path,default=Path.home()/'.dsmack/operator.json')
    p.add_argument('--broker',required=True);p.add_argument('--index',required=True)
    p.add_argument('--publication-rpc',default='https://base-sepolia-rpc.publicnode.com')
    p.add_argument('--ipfs-bin',type=Path);p.add_argument('--ipfs-car',type=Path);p.add_argument('--ipfs-state',type=Path)
    p.add_argument('--registry',required=True);p.add_argument('--publisher-address',required=True)
    a=p.parse_args()
    if any((a.ipfs_bin,a.ipfs_car,a.ipfs_state)) and not all((a.ipfs_bin,a.ipfs_car,a.ipfs_state)):p.error('IPFS needs --ipfs-bin, --ipfs-car and --ipfs-state')
    config=operator_config(a.operator,hardware())
    manifest=json.loads((a.workload/'compose-manifest.json').read_bytes())
    measured_size(manifest,config)
    a.state.mkdir(parents=True,mode=0o700)
    node=json.loads(manifest['docker_compose_file'])['services']['node']
    expected_peer=node['command'][1].rsplit('/',1)[1]
    seconds=int(node['command'][2]);admit=int(node['environment']['ADMIT_SECONDS'])
    while True:
        try:preflight(a.state,[]);break
        except MacOccupied:print('waiting for the active Mac lane',flush=True);time.sleep(10)
    stopping=False;children=[];logs=[];pool=None;published=False;failure=None;published_entries=[]
    def stop(*_):
        nonlocal stopping
        stopping=True
        if pool and pool.poll() is None:
            try:pool.send_signal(signal.SIGTERM)
            except ProcessLookupError:pass
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
            if stopping:raise RuntimeError('stopped during public tunnel readiness')
            if result.get('status')=='ready':return address
            time.sleep(5)
        raise RuntimeError('public tunnel DNS/TLS/WebSocket readiness failed; inspect tunnel-readiness.jsonl')
    pending_path=a.state/'chain-pending.txt'
    def prepare(entries):
        out=a.state/('publication-'+str(time.time_ns()));out.mkdir()
        (out/'entries.json').write_text(json.dumps(entries))
        return out
    def run_publication(out,chain):
        cmd=[sys.executable,ROOT/'applications/browser-p2p/publish.py','chain' if chain else 'broker','--key',a.publisher_key,'--publisher-address',a.publisher_address,'--registry',a.registry,'--broker',a.index,'--entries',out/'entries.json','--evidence',out]
        if chain:cmd+=['--rpc',a.publication_rpc]
        subprocess.run([str(x) for x in cmd],check=True,timeout=480)
    def publish(entries,chain):
        if chain:publish_chain(entries,pending_path,prepare,lambda out:run_publication(out,True))
        else:run_publication(prepare(entries),False)
    try:
        if a.ipfs_bin:start([sys.executable,ROOT/'applications/private-agent-web/pin-mac.py','--ipfs',a.ipfs_bin,'--cloudflared',a.cloudflared,'--car',a.ipfs_car,'--state',a.ipfs_state],'ipfs.log')
        broker_peer=discover_transport(a.broker,lambda:stopping)
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
        published=True;republish(publish,hint,False);last_http=time.monotonic()
        last_chain_attempt=0;published_entries=[]
        if stopping:return
        pool=start([sys.executable,ROOT/'applications/compute-node/pool.py','--runner',a.runner,'--workload',a.workload,'--state',a.state/'guests','--repo',ROOT,'--broker',a.broker,'--seconds',str(seconds),'--drain-seconds',str(seconds-admit),'--replace-after',str(seconds//2+30),'--readiness-timeout','90','--operator',a.operator,'--publisher-key',a.publisher_key,'--publisher-address',a.publisher_address,'--pool-version',a.pool_version],'pool.log')
        draining=False
        while pool.poll() is None:
            for proc in children:
                if proc is not pool and proc.poll() is not None:
                    stopping=True;failure='relay/tunnel/proxy exited; inspect logs'
            if stopping and not draining:
                pool.send_signal(signal.SIGTERM);draining=True;print('draining warm guests',flush=True)
            now=time.monotonic()
            snapshot_path=a.state/'guests/directory.json'
            snapshot=json.loads(snapshot_path.read_text()) if snapshot_path.exists() else {}
            entries=guest_entries(snapshot,hint)
            if (entries!=published_entries or pending_path.exists()) and now-last_chain_attempt>=60:
                last_chain_attempt=now
                published_entries=publish_directory(publish,entries,published_entries,pending_path.exists())
            if now-last_http>=60:
                hint['expiresAt']=int(time.time())+3300
                republish(publish,hint,False);last_http=time.monotonic()
            time.sleep(2)
        if pool.returncode:raise RuntimeError('warm pool failed; inspect pool.log')
        if failure:raise RuntimeError(failure)
    finally:
        if pool and pool.poll() is None:
            pool.send_signal(signal.SIGTERM)
            try:pool.wait(timeout=1000)
            except subprocess.TimeoutExpired:raise RuntimeError('warm guests still active; owned transport retained')
        try:
            if published:
                publish_directory(publish,[],published_entries,pending_path.exists())
                publish([],False)
        finally:
            for proc in reversed(children):
                if proc.poll() is None:proc.terminate()
            for proc in children:
                try:proc.wait(timeout=15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            for log in logs:log.close()
            (a.state/'stopped.json').write_text(json.dumps(dict(stoppedAt=int(time.time()),ownedChildrenStopped=all(c.poll() is not None for c in children),pids=[c.pid for c in children])))

if __name__=='__main__':main()
