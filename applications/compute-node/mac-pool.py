#!/usr/bin/env python3
"""Own a Mac quick tunnel, capped relay and CONNECT helper for the warm pool lifetime."""
import argparse,json,signal,subprocess,sys,time,re,socket,ssl,http.client,base64,hashlib,os,ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from pool import preflight,MacOccupied,hardware,operator_config,measured_size
from pool_restart import Generations, release_config
from pool_handoff import LegacyHandoff
from heartbeat import Publisher

ROOT=Path(__file__).resolve().parents[2]


def republish(publish,entries,chain):
    try:
        publish(entries,chain)
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


def transport_group_running(pgid):
    # A leader can exit before its Kubo/tunnel descendants. Zombies have already
    # closed their descriptors and cannot retain the IPFS repository lock.
    rows = subprocess.check_output(['ps', '-axo', 'pgid=,stat='], text=True)
    return any(int(group) == pgid and not state.startswith('Z')
               for group, state in (row.split()[:2] for row in rows.splitlines() if row.strip()))


def stop_transports(processes, grace_seconds=60):
    """Stop only setsid transport groups spawned by this launcher, never VMs."""
    groups = [proc.pid for proc in processes]
    for proc in reversed(processes):
        if proc.poll() is None:
            proc.terminate()  # Let pin-mac cancel publication and stop its children.
    deadline = time.monotonic() + grace_seconds
    while any(transport_group_running(group) for group in groups) and time.monotonic() < deadline:
        for proc in processes:
            proc.poll()
        time.sleep(.1)
    for group in groups:
        if transport_group_running(group):
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
    for proc in processes:
        proc.wait(timeout=5)
    deadline = time.monotonic() + 5
    while any(transport_group_running(group) for group in groups) and time.monotonic() < deadline:
        time.sleep(.1)
    if any(transport_group_running(group) for group in groups):
        raise RuntimeError('owned transport descendants still active; inspect exact process groups')
    return groups


def process_command(pid):
    result = subprocess.run(['ps', '-o', 'command=', '-p', str(pid)], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def record_transports(path, owner, processes):
    """Record transport groups next to the launcher's generations so a successor can reap them."""
    record = dict(owner=owner, ownerCommand=process_command(owner),
                  groups=[dict(pid=proc.pid, command=process_command(proc.pid)) for proc in processes])
    path.with_suffix('.tmp').write_text(json.dumps(record)); path.with_suffix('.tmp').replace(path)


def reap_orphan_transports(path, grace_seconds=10):
    """Stop transports left by a dead predecessor (killed or crashed before stop_transports ran)."""
    if not path.exists():
        return []
    record = json.loads(path.read_text())
    if record['owner'] != os.getpid() and record['ownerCommand'] and process_command(record['owner']) == record['ownerCommand']:
        raise RuntimeError('pool %d still owns the transports recorded in %s' % (record['owner'], path))
    reaped = []
    for group in record['groups']:
        leader = process_command(group['pid'])
        # A dead leader's pgid can only still be held by its own descendants.
        if (group['command'] and leader == group['command']) or (leader is None and transport_group_running(group['pid'])):
            try:
                os.killpg(group['pid'], signal.SIGTERM); reaped.append(group['pid'])
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + grace_seconds
    while any(transport_group_running(group) for group in reaped) and time.monotonic() < deadline:
        time.sleep(.1)
    for group in reaped:
        if transport_group_running(group):
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
    path.unlink()
    return reaped


class RestartBackoff:
    """Count unfinished starts across launchd's fresh state directories."""
    def __init__(self, path):
        self.path = path
        self.healthy_since = None

    def begin(self, stopped):
        record = json.loads(self.path.read_text()) if self.path.exists() else dict(failures=0, retry_at=0)
        delay = max(0, record['retry_at']-time.time())
        if delay:
            print(json.dumps(dict(event='launcher_retry', failures=record['failures'], retrySeconds=delay)), flush=True)
        while not stopped() and time.time() < record['retry_at']:
            time.sleep(min(1, max(0, record['retry_at']-time.time())))
        if stopped():return False
        failures = record['failures']+1
        delay = min(1800, 60 * 2**min(failures-1, 5))
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(dict(failures=failures, retry_at=time.time()+delay)))
        temporary.replace(self.path)
        return True

    def tick(self, snapshot):
        if not any(slot['state'] in ('ready', 'busy') for slot in snapshot.get('slots', [])):
            self.healthy_since = None
        elif self.healthy_since is None:
            self.healthy_since = time.monotonic()
        elif time.monotonic()-self.healthy_since >= 600 and self.path.exists():
            self.path.unlink()
            print(json.dumps(dict(event='launcher_backoff_reset')), flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('runner','workload','state','relay','relay-key','cloudflared','publisher-key'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--adopt-launcher', type=int, help='one-time transfer of a legacy launcher and its live guests')
    p.add_argument('--restart-config', type=Path, help='replacement JSON read on SIGHUP')
    p.add_argument('--restart-timeout', type=float, default=300)
    p.add_argument('--key-rotation', type=Path, help='key_rotation.py config passed to each guest generation')
    p.add_argument('--pool-version',required=True,help='source commit used by this staged pool')
    p.add_argument('--operator',type=Path,default=Path.home()/'.dsmack/operator.json')
    p.add_argument('--max-slots',type=int,help='cap the operator guest slots for this pool')
    p.add_argument('--coexist-pool',type=Path,action='append',default=[],help='allow guests owned by launcher state anywhere beneath this directory')
    p.add_argument('--relay-port',type=int,default=4019)
    p.add_argument('--broker',required=True);p.add_argument('--index',required=True)
    p.add_argument('--publication-rpc',action='append',help='ordered publication RPC; repeat for several providers')
    p.add_argument('--ipfs-bin',type=Path);p.add_argument('--ipfs-car',type=Path);p.add_argument('--ipfs-state',type=Path)
    p.add_argument('--registry',required=True);p.add_argument('--publisher-address',required=True)
    a=p.parse_args()
    if any((a.ipfs_bin,a.ipfs_car,a.ipfs_state)) and not all((a.ipfs_bin,a.ipfs_car,a.ipfs_state)):p.error('IPFS needs --ipfs-bin, --ipfs-car and --ipfs-state')
    config=operator_config(a.operator,hardware(),a.max_slots)
    if not 1 <= a.relay_port <= 65535:p.error('--relay-port must be 1..65535')
    manifest=json.loads((a.workload/'compose-manifest.json').read_bytes())
    measured_size(manifest,config)
    a.state=a.state.resolve()
    if not a.adopt_launcher:a.state.mkdir(parents=True,mode=0o700)
    node=json.loads(manifest['docker_compose_file'])['services']['node']
    proxy_port=urlsplit(node['environment']['HTTPS_PROXY']).port
    expected_peer=node['command'][1].rsplit('/',1)[1]
    initial=release_config(a.runner,a.workload,a.operator,a.pool_version,expected_peer)
    for path in (a.relay,a.relay_key,a.cloudflared,a.publisher_key):
        if not path.is_file():raise FileNotFoundError(path)
    while not a.adopt_launcher:
        try:preflight(a.state,[],coexist_pools=a.coexist_pool+[a.state.parent]);break  # a killed predecessor's guests drain on their own
        except MacOccupied:print('waiting for the active Mac lane',flush=True);time.sleep(10)
    transport_record=a.state.parent/'transports.json'
    if not a.adopt_launcher:
        reaped=reap_orphan_transports(transport_record)
        if reaped:print(json.dumps(dict(event='reaped_orphan_transports',groups=reaped)),flush=True)
    stopping=False;reload_requested=False;children=[];transports=[];logs=[];pools=None;handoff=None;published=False;published_entries=[]
    def stop(*_):
        nonlocal stopping
        stopping=True
    def reload(*_):
        nonlocal reload_requested
        reload_requested=True
    signal.signal(signal.SIGHUP,reload)
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    def start(command,name,transport=True):
        log=(a.state/name).open('w');logs.append(log)
        proc=subprocess.Popen([str(x) for x in command],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=transport)
        children.append(proc)
        if transport:transports.append(proc);record_transports(transport_record,os.getpid(),transports)
        return proc
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
        cmd=[sys.executable,ROOT/'applications/browser-p2p/publish.py','chain' if chain else 'broker','--key',a.publisher_key,'--publisher-address',a.publisher_address,'--registry',a.registry,'--broker',a.index,'--entries',out/'entries.json','--evidence',out,'--expiry-state',a.state.parent/'publication-expiry']
        if chain:
            for url in a.publication_rpc or ['https://base-sepolia-rpc.publicnode.com', 'https://base-sepolia.gateway.tenderly.co', 'https://sepolia.base.org']:
                cmd+=['--rpc',url]
        subprocess.run([str(x) for x in cmd],check=True,timeout=480)
    def publish(entries,chain):
        if chain:publish_chain(entries,pending_path,prepare,lambda out:run_publication(out,True))
        else:run_publication(prepare(entries),False)
    backoff=RestartBackoff(a.state.parent/'launcher-backoff.json')
    try:
        if not a.adopt_launcher and not backoff.begin(lambda:stopping):return
        if a.adopt_launcher:
            handoff=LegacyHandoff(a.adopt_launcher,a.state)
            transports.extend(handoff.transports)
            children.extend(handoff.transports)
            hint=json.loads((a.state/'locator.json').read_bytes())
            if hint['relayPeer']!=expected_peer:raise ValueError('legacy relay differs from measured compose')
            published=True;last_http=0;last_chain_attempt=0;published_entries=[]
        else:
            if a.ipfs_bin:start([sys.executable,ROOT/'applications/private-agent-web/pin-mac.py','--ipfs',a.ipfs_bin,'--cloudflared',a.cloudflared,'--car',a.ipfs_car,'--state',a.ipfs_state],'ipfs.log')
            broker_peer=discover_transport(a.broker,lambda:stopping)
            relay_command=[a.relay]
            if a.relay_port!=4019:relay_command+=['-port',str(a.relay_port)]
            start(relay_command+[a.relay_key,a.broker.rstrip('/')+'/sandbox/p2p',broker_peer],'relay.log')
            relay=ready(a.state/'relay.log',r'relay_peer=(12D3KooW\S+)',30)
            if relay!=expected_peer:raise ValueError('relay key does not match the measured compose')
            start([a.cloudflared,'tunnel','--no-autoupdate','--url',f'http://127.0.0.1:{a.relay_port}'],'tunnel.log')
            host=ready(a.state/'tunnel.log',r'https://([a-z0-9-]+\.trycloudflare\.com)',90)
            ready(a.state/'tunnel.log',r'(Registered tunnel connection)',90)
            tunnel_address=public_ready(host)
            broker_host=urlsplit(a.broker).hostname;broker_address=resolve(broker_host)
            start([sys.executable,ROOT/'applications/compute-node/connect-proxy.py','--listen','127.0.0.1','--port',str(proxy_port),'--allow-host',host,'--allow-host',urlsplit(a.broker).hostname,'--connection-seconds','3600','--resolve',host+'='+tunnel_address,'--resolve',broker_host+'='+broker_address],'proxy.log')
            hint=dict(url='wss://'+host+'/',relayPeer=relay,expiresAt=int(time.time())+3300)
            (a.state/'locator.json').write_text(json.dumps(hint,indent=2))
            published=True;republish(publish,[hint],False);last_http=time.monotonic()
            last_chain_attempt=0;published_entries=[]
            if stopping:return
        publisher=Publisher(a.publisher_key,a.publisher_address,a.broker,a.pool_version,a.operator)
        pools=Generations(a.state,a.broker,publisher,start,expected_peer,a.restart_timeout,a.max_slots,a.coexist_pool,a.key_rotation)
        pools.current=pools.launch(initial,a.state/'guests' if handoff else None)
        if handoff:
            deadline=time.monotonic()+30
            while not (pools.current['state']/'adopted.json').exists():
                if pools.current['process'].poll() is not None or time.monotonic()>=deadline:
                    raise RuntimeError('legacy transfer failed; inspect new pool log')
                time.sleep(.1)
            handoff.commit()
            record_transports(transport_record,os.getpid(),transports)
        (a.state/'launcher.pid').write_text(str(os.getpid()))
        while not stopping:
            for proc in transports:
                if proc.poll() is not None:
                    raise RuntimeError('relay/tunnel/proxy exited; inspect logs')
            if reload_requested:
                reload_requested=False
                try:
                    if not a.restart_config:raise ValueError('--restart-config is required for SIGHUP')
                    pools.restart(a.restart_config)
                except (OSError,ValueError,KeyError,TypeError) as error:
                    print(json.dumps(dict(event='restart_rejected',error=str(error))),flush=True)
            snapshot=pools.tick() or {}
            backoff.tick(snapshot)
            now=time.monotonic()
            entries=guest_entries(snapshot,hint)
            if (entries!=published_entries or pending_path.exists()) and now-last_chain_attempt>=60:
                last_chain_attempt=now
                published_entries=publish_directory(publish,entries,published_entries,pending_path.exists())
            if now-last_http>=60:
                hint['expiresAt']=int(time.time())+3300
                republish(publish,[hint],False);last_http=time.monotonic()
            time.sleep(2)
    finally:
        if a.adopt_launcher and (handoff is None or not handoff.committed):
            # A failed adoption must leave the old controller and transports live.
            if pools:pools.stop()
            if handoff:handoff.resume()
            for log in logs:log.close()
        else:
            finish(pools, published, published_entries, pending_path, publish, transports, logs, children, a.state)
            if stopping:(a.state.parent/'launcher-backoff.json').unlink(missing_ok=True)  # a requested stop is not a failed start

def finish(pools, published, published_entries, pending_path, publish, transports, logs, children, state):
    try:
        if pools:pools.stop()
        if published:
            publish_directory(publish,[],published_entries,pending_path.exists())
            republish(publish,[],False)
    finally:
        groups=stop_transports(transports)
        (state.parent/'transports.json').unlink(missing_ok=True)
        for log in logs:log.close()
        (state/'stopped.json').write_text(json.dumps(dict(stoppedAt=int(time.time()),
            ownedChildrenStopped=all(c.poll() is not None for c in children),
            ownedTransportGroupsStopped=groups,pids=[c.pid for c in children])))

if __name__=='__main__':main()
