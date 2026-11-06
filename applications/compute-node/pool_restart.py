"""Make-before-break generations behind one launcher's relay and proxy."""
import json
from pathlib import Path
import signal
import sys
import time
from http.client import HTTPException
from urllib.request import urlopen

from pool import hardware, operator_config, sha, validate_config, ready_node


def release_config(runner, workload, operator, version, peer, source=Path(__file__).resolve().parents[2]):
    runner, workload, operator = (Path(p).resolve() for p in (runner, workload, operator))
    source = Path(source).resolve()
    manifest = validate_config(runner, workload, operator_config(operator, hardware()))
    node = json.loads(manifest['docker_compose_file'])['services']['node']
    if node['command'][1].rsplit('/', 1)[1] != peer:
        raise ValueError('replacement requires the existing measured relay peer')
    seconds = int(node['command'][2])
    drain = seconds - int(node['environment']['ADMIT_SECONDS'])
    replace = seconds//2 + 30
    if (not 1 <= seconds <= 3600 or not 1 <= drain < seconds
            or max(replace, seconds-replace) + 90 >= seconds-drain):
        raise ValueError('replacement must attest before admission closes')
    return dict(source=source, runner=runner, workload=workload, operator=operator, version=version,
                seconds=seconds, drain=drain, replace=replace,
                measurement=sha(workload/'compose-manifest.json'), image=manifest['base_vm']['os_image_hash'])


def replacement(path, peer):
    value = json.loads(path.read_bytes())
    config = release_config(value['runner'], value['workload'], value['operator'], value['pool_version'], peer, value['source'])
    for path, expected in ((config['workload']/'workload.img', value['workload_sha256']),
                           (config['workload']/'compose-manifest.json', value['manifest_sha256'])):
        if sha(path) != expected:
            raise ValueError('SHA256 mismatch: ' + str(path))
    return config


def combine(generations):
    """One heartbeat retains busy guests and discovery entries throughout overlap."""
    snapshots = []
    for generation in generations:
        path = generation['state']/'directory.json'
        if path.exists():
            snapshots.append(json.loads(path.read_bytes()))
    if not snapshots:
        return None
    result = dict(snapshots[-1], slots=[], classes=[], errors=[])
    offset = 0
    for snapshot in snapshots:
        result['slots'].extend(dict(slot, slot_id=slot['slot_id']+offset) for slot in snapshot['slots'])
        offset += snapshot['config']['max_guests']
        result['classes'].extend(snapshot['classes'])
        result['errors'].extend(snapshot['errors'])
    result['config'] = dict(result['config'], max_guests=offset)
    result['classes'] = sorted(set(result['classes']))
    result['errors'] = result['errors'][-10:]
    return result


class Generations:
    def __init__(self, root, broker, publisher, start, peer, timeout=300, max_slots=None, coexist_pools=(), key_rotation=None):
        self.root, self.broker, self.publisher = root, broker, publisher
        self.start, self.peer, self.timeout = start, peer, timeout
        self.pools = []
        self.current = self.candidate = None
        self.deadline = 0
        self.max_slots, self.coexist_pools, self.key_rotation = max_slots, coexist_pools, key_rotation

    def launch(self, config, adopt_state=None):
        state = self.root/('guests-'+str(time.time_ns()))
        state.mkdir()
        command = [sys.executable, config['source']/'applications/compute-node/pool.py',
                   '--runner', config['runner'], '--workload', config['workload'], '--state', state,
                   '--pool-root', self.root, '--broker', self.broker, '--seconds', str(config['seconds']),
                   '--drain-seconds', str(config['drain']), '--replace-after', str(config['replace']),
                   '--operator', config['operator']]
        if adopt_state:
            command += ['--adopt-state', adopt_state]
        if self.max_slots is not None:
            command += ['--max-slots', str(self.max_slots)]
        for root in self.coexist_pools:
            command += ['--coexist-pool', root]
        if self.key_rotation:
            command += ['--key-rotation', self.key_rotation]
        generation = dict(config=config, state=state, process=self.start(command, state.name+'.log', transport=False))
        self.pools.append(generation)
        return generation

    def restart(self, path):
        if len(self.pools) != 1:
            raise ValueError('a replacement or drain is already in progress')
        config = replacement(path, self.peer)  # Complete validation before Popen.
        self.ready_heartbeat = None
        self.candidate = self.launch(config)
        self.deadline = time.monotonic() + self.timeout
        print(json.dumps(dict(event='replacement_started', state=str(self.candidate['state']))), flush=True)

    def read(self, path):
        with urlopen(self.broker.rstrip('/')+path, timeout=5) as response:
            return json.load(response)

    def replacement_ready(self, snapshot):
        config = self.candidate['config']
        peers = {slot['relay_peer'] for slot in snapshot['slots'] if slot['state'] == 'ready'}
        # /nodes supplies live broker-verified identities, /network confirms that
        # our combined heartbeat is visible to browsers before draining anything.
        live = [node for node in self.read('/nodes') if node['relay_peer'] in peers
                and node['admit_until'] > int(time.time()) and not node.get('telemetry', {}).get('busy')]
        node = ready_node(live, set(), config['measurement'], config['image'])
        network = self.read('/network')
        return node and any(mac['publisher'] == self.publisher.account.address.lower()
                            and mac['online'] and mac['ready'] > 0
                            and mac['last_heartbeat'] >= self.ready_heartbeat
                            for mac in network['macs'])

    def tick(self):
        for generation in self.pools[:]:
            code = generation['process'].poll()
            if code is None:
                continue
            self.pools.remove(generation)
            if generation is self.candidate:
                self.candidate = None
                print(json.dumps(dict(event='replacement_failed', exit_code=code)), flush=True)
            elif generation is self.current:
                raise RuntimeError('serving pool exited; inspect '+str(generation['state']))
            elif code:
                print(json.dumps(dict(event='draining_pool_failed', exit_code=code, state=str(generation['state']))), flush=True)
        snapshot = combine(self.pools)
        heartbeat = self.publisher.tick(snapshot) if snapshot else None
        if heartbeat:
            print(json.dumps(heartbeat), flush=True)
        if not self.candidate:
            return snapshot
        candidate_snapshot = combine([self.candidate])
        candidate_ready = candidate_snapshot and any(slot['state'] == 'ready' for slot in candidate_snapshot['slots'])
        if candidate_ready and heartbeat and heartbeat['event'] == 'heartbeat_posted':
            self.ready_heartbeat = heartbeat['updated_at']
        if candidate_ready and self.ready_heartbeat is not None:
            try:
                ready = self.replacement_ready(candidate_snapshot)
            except (OSError, HTTPException, ValueError, KeyError, TypeError) as error:
                print(json.dumps(dict(event='replacement_readiness_error', error=str(error))), flush=True)
                ready = False
            if ready:
                old = self.current
                self.current, self.candidate = self.candidate, None
                self.publisher.version = self.current['config']['version']
                self.publisher.operator_path = self.current['config']['operator']
                old['process'].send_signal(signal.SIGTERM)
                print(json.dumps(dict(event='replacement_ready_draining_old', state=str(old['state']))), flush=True)
        if self.candidate and time.monotonic() >= self.deadline:
            self.candidate['process'].send_signal(signal.SIGTERM)
            self.candidate = None
            print(json.dumps(dict(event='replacement_timeout', action='retaining serving pool; draining candidate')), flush=True)
        return snapshot

    def stop(self):
        for generation in self.pools:
            if generation['process'].poll() is None:
                generation['process'].send_signal(signal.SIGTERM)
        deadline = time.monotonic()+4300
        while True:
            running = [g for g in self.pools if g['process'].poll() is None]
            if not running:
                break
            if time.monotonic() >= deadline:
                import subprocess
                raise subprocess.TimeoutExpired('draining pools', 4300)
            snapshot = combine(running)
            if snapshot:
                heartbeat = self.publisher.tick(snapshot)
                if heartbeat:
                    print(json.dumps(heartbeat), flush=True)
            time.sleep(2)
        for generation in self.pools:
            generation['process'].wait(timeout=5)
