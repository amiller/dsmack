#!/usr/bin/env python3
"""Keep a verified compute node warm; run locally on the operator Mac."""
import argparse
import ast
import gzip
import fcntl
import hashlib
import json
import os
import socket
from pathlib import Path
from http.client import HTTPException
import runpy
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

HERE = Path(__file__).resolve().parent


class MacOccupied(RuntimeError):
    pass


class BrokerUnavailable(RuntimeError):
    pass


def hardware():
    def sysctl(name):
        return subprocess.check_output(['sysctl', '-n', name], text=True).strip()
    return {'name': socket.gethostname(), 'model': sysctl('hw.model'),
            'chip': sysctl('machdep.cpu.brand_string'), 'mem_bytes': int(sysctl('hw.memsize')),
            'cores': int(sysctl('hw.ncpu'))}


def operator_config(path, host, max_slots=None):
    config = json.loads(path.read_bytes())
    from heartbeat import operator_region
    operator_region(path)
    fields = [('max_guests', config.get('max_guests'), 1),
              ('guest.mem_mib', config.get('guest', {}).get('mem_mib'), 1),
              ('guest.vcpus', config.get('guest', {}).get('vcpus'), 1),
              ('reserve.mem_gb', config.get('reserve', {}).get('mem_gb'), 0),
              ('reserve.cores', config.get('reserve', {}).get('cores'), 0)]
    for name, value, minimum in fields:
        if type(value) is not int or value < minimum:
            raise ValueError(f'operator {name} must be an integer >= {minimum}')
    if max_slots is not None:
        if type(max_slots) is not int or max_slots < 1:
            raise ValueError('max slots must be a positive integer')
        config['max_guests'] = min(config['max_guests'], max_slots)
    guests, size, reserve = config['max_guests'], config['guest'], config['reserve']
    wanted_mem = guests * size['mem_mib']
    total_mem = host['mem_bytes'] // (1 << 20)
    reserve_mem = reserve['mem_gb'] * 1024
    wanted_cores = guests * size['vcpus']
    if wanted_mem > total_mem-reserve_mem or wanted_cores > host['cores']-reserve['cores']:
        raise ValueError(f"operator capacity refused: {guests} guests × {size['mem_mib']} MiB = {wanted_mem} MiB; "
                         f"physical {total_mem} MiB - reserve {reserve_mem} MiB = {total_mem-reserve_mem} MiB available; "
                         f"{guests} × {size['vcpus']} vCPUs = {wanted_cores}; "
                         f"physical {host['cores']} cores - reserve {reserve['cores']} = {host['cores']-reserve['cores']} available")
    return config


def measured_size(manifest, config):
    size = config['guest']
    profile = f"mini-{size['mem_mib']}-{size['vcpus']}"
    if (manifest['base_vm'].get('memory_mb') != size['mem_mib']
            or manifest['base_vm'].get('vcpus') != size['vcpus']):
        raise ValueError(f'operator guest size {size} differs from measured resource profile {profile}; repack and register its node class')
    return profile


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_config(runner, workload, config):
    """Reject a staged release with missing or mismatched launch inputs before boot."""
    def match(path, expected):
        if sha(path) != expected:
            raise ValueError('SHA256 mismatch: ' + str(path))
    manifest = json.loads((workload/'compose-manifest.json').read_bytes())
    measured_size(manifest, config)
    base = manifest['base_vm']
    for filename, field in [('Image', 'kernel_sha256'), ('initramfs.cpio.gz', 'initrd_sha256'),
                            ('rootfs.squashfs.verity', 'rootfs_sha256'), ('metadata.json', 'metadata_sha256'),
                            ('sha256sum.txt', 'os_image_hash')]:
        match(runner/'base'/filename, base[field])
    meta = json.loads((runner/'base/metadata.json').read_bytes())
    cmdline = dict(x.split('=', 1) for x in meta['cmdline'].split() if '=' in x)
    for name in ('scratch', 'result'):
        match(runner/'runtime/base'/(name+'-template.ext4'), cmdline['dstack.'+name+'_template_sha256'])
    for path in (runner/'DsmackRunner.app/Contents/MacOS/dsmack-runner',
                 runner/'runtime/helper/gvproxy-darwin', runner/'enrollment/keyId.txt', workload/'workload.img'):
        if not path.is_file():
            raise FileNotFoundError(path)
    return manifest


def ready_node(nodes, previous, measurement, image):
    return next((n for n in nodes if n['relay_peer'] not in previous and n.get('kind') == 'compute'
                 and n.get('manifest_sha256') == measurement and n.get('os_image_hash') == image
                 and n.get('attestation', {}).get('status') == 'verified'), None)


def should_replace(active, now, replace_after):
    serving = [n for n in active if n.get('node') and now < n['started'] + n['admit_seconds']]
    return not serving or now - max(n['started'] for n in serving) >= replace_after


def preflight(state, active, pool_root=None, coexist_pools=()):
    free = shutil.disk_usage(state).free
    if free < 12 * (1 << 30):
        raise RuntimeError('less than 12 GiB free on Mac')
    result = subprocess.run(['pgrep', '-fl', 'MacOS/dsmack-runner'], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError('Mac runner process probe failed')
    owned_sessions = {str(n['path']/'session.json') for n in active}
    if pool_root:
        owned_sessions.update(str(path) for path in pool_root.glob('*/run-*/session.json'))
    allowed_sessions = set()
    for root in coexist_pools:
        allowed_sessions.update(str(path.resolve()) for path in root.glob('**/run-*/session.json'))
    for line in result.stdout.splitlines():
        pid = int(line.split()[0])
        command = subprocess.check_output(['ps', '-p', str(pid), '-o', 'command='], text=True)
        if not (owned_sessions | allowed_sessions).intersection(shlex.split(command)):
            raise MacOccupied('another lane owns the active Mac VM; waiting')
    return {'free_bytes': free, 'owned_runner_sessions': sorted(owned_sessions)}


def stopped_helper(run):
    helper = json.loads((run/'helper-stopped.json').read_bytes())
    try:
        os.kill(helper['pid'], 0)
    except ProcessLookupError:
        return helper
    raise RuntimeError('owned network helper remains active')


def error_details(message, stage, **fields):
    details = {'stage': stage, 'error': message, **fields}
    match = re.search(r'(POST [^ :]+): HTTP (\d+) body=("(?:[^"\\]|\\.)*")', message)
    if match:
        request_stage = 'broker_registration' if match[1].endswith('/nodes') else match[1]
        details.update(stage=request_stage if stage in ('node_gateway_error', 'guest_stderr') else stage, status=int(match[2]),
                       body=ast.literal_eval(match[3]))
    elif re.search(r'(?:Get|Post) "https?://[^\s"]+/(?:payments/challenge|nodes)"', message):
        if stage in ('node_gateway_error', 'guest_stderr'):
            details['stage'] = 'broker_registration'
    elif match := re.search(r'payment challenge: HTTP (\d+)', message):
        details.update(stage='broker_registration', status=int(match[1]))
    return details


def external_broker_error(error):
    """Chain unavailability and transport failures cannot consume a guest strike."""
    if not error:
        return False
    stage = error.get('stage', '')
    message = error.get('error', '') + ' ' + error.get('body', '')
    if not (stage.startswith('broker') or re.search(r'(?:POST |Post ").*/nodes', message)):
        return False
    return bool(re.search(r'RPC (?:quorum|HTTP|eth_)|finalized RPC quorum|stale/future finalized head|finalized block (?:stale|future)', message, re.I)
                or error.get('status') in (408, 429, 502, 503, 504)
                or (error.get('status') is None and re.search(
                    r'connection refused|connection reset|timeout|timed out|no such host|dial tcp|network is unreachable|EOF', message, re.I)))


def guest_result(run, debugfs):
    """Read diagnostic exports after the owned helper stops; retain exact bytes."""
    stopped_helper(run)
    out = run/'out'
    def read(path):
        result = subprocess.run([str(debugfs), '-R', 'cat /compute-node-v1/'+path, str(out/'result.img')],
                                capture_output=True, check=True, timeout=20)
        diagnostic = result.stderr.decode(errors='replace').splitlines()
        if any(line and not line.startswith('debugfs ') for line in diagnostic):
            raise RuntimeError('debugfs '+path+': '+'; '.join(diagnostic))
        return result.stdout
    try:
        raw = read('receipt.json')
        (out/'guest-receipt.json').write_bytes(raw)
        outputs = json.loads(raw)['outputs']
        captured = {}
        declarations = [('stderr', outputs.get('stderr'), 'outputs/streams/stderr', 'guest-stderr.log')]
        exports = {'gateway-log': 'gateway-log.jsonl', 'agent-receipts': 'agent-receipts.jsonl',
                   'tool-server-log': 'tool-server.log'}
        declarations += [(item['name'], item, 'outputs/artifacts/'+item['name'], exports[item['name']])
                         for item in outputs.get('artifacts', []) if item['name'] in exports]
        for name, declared, source, target in declarations:
            if declared is None or name in outputs.get('missing', []):
                continue
            data = read(source)
            if len(data) != declared['bytes'] or hashlib.sha256(data).hexdigest() != declared['sha256']:
                raise RuntimeError('result diagnostic export differs from receipt: '+name)
            (out/target).write_bytes(data)
            captured[name] = data.decode(errors='replace')
        last_error = None
        for line in captured.get('gateway-log', '').splitlines():
            if not line.startswith('{'):
                continue
            record = json.loads(line)
            if record.get('error'):
                last_error = error_details(record['error'], record.get('stage', record.get('event', 'guest_gateway')),
                                           terminal=record.get('event') == 'node_gateway_error')
        stderr = captured.get('stderr', '').strip()
        if stderr:
            # The terminal Go error follows any renewal attempts in stderr.
            line = stderr.splitlines()[-1]
            terminal = bool(re.match(r'^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ', line))
            last_error = error_details(line, (last_error or {}).get('stage', 'guest_stderr'),
                                       terminal=terminal or (last_error or {}).get('terminal', False))
        return {'outputs': outputs, 'error': last_error}
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        return {'error': {'stage': 'result_extraction', 'error': str(error)}}


def guest_closed(run):
    console = run/'out/console-v3.log'
    if not console.is_file():
        return False
    lines = console.read_text(errors='replace').splitlines()
    return ('DSMACK_SUPERVISOR_DONE runner_failures=0' in lines
            and any(line.startswith('DSMACK_RESULT_CLOSED_V1 ') for line in lines))


def preserve_and_retire(run, repo):
    """Keep original evidence before removing the exact stopped attempt's disks."""
    helper = stopped_helper(run)
    evidence = run/'evidence'; evidence.mkdir(exist_ok=True)
    out = run/'out'
    for directory in (run, out):
        if not directory.exists():
            continue
        target = evidence if directory == run else evidence/'out'
        target.mkdir(exist_ok=True)
        for source in directory.iterdir():
            if source.is_file() and source.suffix in ('.json', '.jsonl', '.log', '.bin', '.cbor', '.txt'):
                shutil.copyfile(source, target/source.name)
    result = out/'result.img'
    if not result.is_file():
        raise RuntimeError('owned VM produced no original result disk; preserve attempt')
    original_hash = sha(result)
    packed = evidence/'result.img.gz'
    with result.open('rb') as src, packed.open('wb') as dest:
        with gzip.GzipFile(filename='', fileobj=dest, mode='wb', mtime=0) as gz:
            shutil.copyfileobj(src, gz, 1 << 20)
    digest = hashlib.sha256()
    with gzip.open(packed, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    if digest.hexdigest() != original_hash:
        raise RuntimeError('preserved result differs from original')
    paths = [run/'workload.img'] + [out/n for n in ('scratch.img', 'scratch-template.img.staged',
             'result-template.img.staged', 'system.img.staged', 'workload.img.staged', 'result.img') if (out/n).exists()]
    no_refs = runpy.run_path(str(repo/'applications/bounties/runner/cleanup.py'))['no_refs']
    no_refs(paths)
    snapshots = []
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise RuntimeError('retirement path is not an exact owned regular file')
        snapshots.append((path, info))
    before = shutil.disk_usage(run).free
    for path, info in snapshots:
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise RuntimeError('retirement path changed')
        path.unlink()
    record = {'result_sha256': original_hash, 'result_original': str(packed),
              'retired_allocated_bytes': sum(s.st_blocks*512 for _, s in snapshots),
              'free_before': before, 'free_after': shutil.disk_usage(run).free, 'helper_stopped': helper}
    (evidence/'cleanup.json').write_text(json.dumps(record))
    return record


class Pool:
    def __init__(self, args):
        self.args = args
        self.boot_lock = None
        self.active = []
        self.launched = 0
        self.stopping = False
        self.hardware = hardware()
        self.config = operator_config(args.operator, self.hardware, getattr(args, 'max_slots', None))
        self.slots = [{'slot_id': i, 'consecutive_failures': 0, 'last_error': None,
                       'retry_pending': False, 'stopped': False, 'jobs_served': 0}
                      for i in range(self.config['max_guests'])]
        self.errors_file = args.operator.parent/'operator-errors.json'
        try:
            self.errors = json.loads(self.errors_file.read_bytes())[-10:]
        except FileNotFoundError:
            self.errors = []
        self.last_broker_error = None
        self.last_status_poll = 0
        self.manifest = args.workload/'compose-manifest.json'
        self.measurement = sha(self.manifest)
        manifest = json.loads(self.manifest.read_bytes())
        self.profile = measured_size(manifest, self.config)
        self.image = manifest['base_vm']['os_image_hash']
        self.payments = json.loads(json.loads(manifest['docker_compose_file'])['services']['node']['environment']['PAYMENTS_CONFIG'])
        self.publisher = None
        if args.publisher_key:
            from heartbeat import Publisher
            self.publisher = Publisher(args.publisher_key, args.publisher_address, args.broker, args.pool_version, args.operator)
        self.started = time.monotonic()

    def remember_error(self, record):
        self.errors = (self.errors + [record])[-10:]
        temporary = self.errors_file.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.errors, ensure_ascii=False))
        temporary.replace(self.errors_file)

    def event(self, name, **fields):
        record = {'event': name, 'elapsed_seconds': round(time.monotonic()-self.started, 3), **fields}
        print(json.dumps(record), flush=True)
        with (self.args.state/'pool.jsonl').open('a') as log:
            log.write(json.dumps(record)+'\n')

    def retry_broker(self, slot, error):
        delay = min(900, max(60, slot.get('broker_backoff', 0) * 2))
        slot.update(broker_backoff=delay, retry_at=time.monotonic()+delay,
                    retry_pending=True, last_error=error)
        self.event('broker_retry', slot_id=slot['slot_id'], retry_seconds=delay, last_error=error)

    def nodes(self):
        raw = b''
        status = None
        try:
            with urlopen(self.args.broker.rstrip('/')+'/nodes?all=1', timeout=20) as response:
                status = response.status
                raw = response.read((1 << 20) + 1)
            if len(raw) > 1 << 20:
                raise ValueError('broker node index exceeds 1 MiB')
            nodes = json.loads(raw)
            if not isinstance(nodes, list):
                raise ValueError('broker node index is not an array')
            self.last_broker_error = None
            return nodes
        except (OSError, HTTPException, ValueError) as error:
            details = {'stage': 'broker_readiness', 'error': str(error), 'error_type': type(error).__name__,
                       'status': getattr(error, 'code', status), 'body': raw[:4096].decode(errors='replace')}
            if isinstance(error, HTTPError):
                try:
                    details['body'] = error.read(4096).decode(errors='replace')
                except (OSError, TimeoutError, HTTPException) as read_error:
                    details['body_read_error'] = str(read_error)
                finally:
                    error.close()
            self.last_broker_error = details
            self.event('broker_unavailable', **details)
            return None

    def launch(self, slot):
        check = preflight(self.args.state, self.active, self.args.pool_root, self.args.coexist_pool)
        nodes = self.nodes()
        if nodes is None:
            raise BrokerUnavailable()
        baseline = {n['relay_peer'] for n in nodes}
        run = self.args.state/('run-'+str(time.time_ns())); run.mkdir(mode=0o700)
        # macOS clone preserves one explicit transfer basis without rewriting it.
        subprocess.run(['cp', '-c', str(self.args.workload/'workload.img'), str(run/'workload.img')], check=True)
        shutil.copyfile(self.manifest, run/'compose-manifest.json')
        (run/'preflight.json').write_text(json.dumps(check))
        log = (run/'host-run.log').open('wb')
        proc = subprocess.Popen([sys.executable, str(HERE/'pool_mac_run.py'), str(self.args.runner), str(run),
                                 str(self.args.seconds), self.profile], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        self.launched += 1
        node = {'slot_id': slot['slot_id'], 'started_at': int(time.time()), 'process': proc, 'path': run, 'started': time.monotonic(), 'node': None, 'previous': baseline,
                'admit_seconds': self.args.seconds-self.args.drain_seconds, 'readiness_deadline': time.monotonic()+self.args.readiness_timeout}
        self.active.append(node)
        slot['retry_pending'] = False
        self.event('launch', slot_id=slot['slot_id'], run=str(run), driver_pid=proc.pid)

    def tick(self):
        if self.boot_lock and not any(n['node'] is None for n in self.active):
            self.boot_lock.close()
            self.boot_lock = None
        now = time.monotonic()
        if any(n['node'] for n in self.active) and now-self.last_status_poll >= 15:
            current = self.nodes()
            self.last_status_poll = now
            if current is not None:
                by_peer = {n['relay_peer']: n for n in current}
                for node in self.active:
                    if node['node'] and node['node']['relay_peer'] in by_peer:
                        latest = by_peer[node['node']['relay_peer']]
                        error = latest.get('telemetry', {}).get('last_error')
                        if error and error != node['node'].get('telemetry', {}).get('last_error'):
                            slot = self.slots[node['slot_id']]
                            slot['last_error'] = {'stage': 'guest_job', 'error': error}
                            self.remember_error({'at': int(time.time()), 'slot_id': slot['slot_id'], **slot['last_error']})
                        node['node'] = latest
        for node in self.active[:]:
            slot = self.slots[node['slot_id']]
            proc = node['process']
            if proc.poll() is not None:
                result = guest_result(node['path'], self.args.debugfs)
                outputs = result.get('outputs', {})
                normal_timeout = (outputs.get('status') == 'cancelled'
                                  and (outputs.get('cancel') or {}).get('reason') == 'timeout'
                                  and (not result.get('error') or result['error'].get('terminal') is False))
                closed = guest_closed(node['path'])
                failed = (proc.returncode != 0 or node['node'] is None or node.get('readiness_failed')
                          or not closed or not (outputs.get('status') == 'completed' or normal_timeout))
                cleanup = preserve_and_retire(node['path'], self.args.repo)
                if failed:
                    slot['retry_pending'] = True
                    actual_error = result.get('error')
                    if not actual_error or actual_error.get('stage') == 'result_extraction':
                        actual_error = node.get('readiness_error') or actual_error
                    slot['last_error'] = actual_error or {
                        'stage': 'guest_completion', 'error': 'guest exited without broker readiness and successful result closure',
                        'exit_code': result.get('outputs', {}).get('exit_code'), 'driver_exit_code': proc.returncode}
                    (node['path']/'evidence/guest-error.json').write_text(json.dumps(slot['last_error'])+'\n')
                    self.remember_error({'at': int(time.time()), 'slot_id': slot['slot_id'], **slot['last_error']})
                    external = closed and external_broker_error(slot['last_error'])
                    if not external:
                        slot['consecutive_failures'] += 1
                    self.event('guest_failed', slot_id=slot['slot_id'], run=str(node['path']), consecutive_failures=slot['consecutive_failures'],
                               last_error=slot['last_error'], **cleanup)
                    if external:
                        self.retry_broker(slot, slot['last_error'])
                    else:
                        if slot['consecutive_failures'] >= 3:
                            slot['stopped'] = True
                            self.event('failure_limit', slot_id=slot['slot_id'], consecutive_failures=slot['consecutive_failures'], last_error=slot['last_error'])
                else:
                    slot['consecutive_failures'] = 0
                    slot.update(broker_backoff=0, retry_at=0)
                    self.event('retired', slot_id=slot['slot_id'], run=str(node['path']), last_error=result.get('error'), **cleanup)
                slot['jobs_served'] += (node['node'] or {}).get('telemetry', {}).get('jobs_served', 0)
                self.active.remove(node)
                continue
            if node['node'] is None and not self.stopping:
                nodes = self.nodes()
                if nodes is None:
                    node['readiness_error'] = self.last_broker_error
                    node['readiness_deadline'] = now + self.args.readiness_timeout
                    continue
                claimed = {n['node']['relay_peer'] for n in self.active if n['node']}
                found = ready_node(nodes, node['previous'] | claimed, self.measurement, self.image)
                if found:
                    node['node'] = found
                    node.pop('readiness_failed', None)
                    node.pop('readiness_error', None)
                    self.event('ready', slot_id=slot['slot_id'], run=str(node['path']), relay_peer=found['relay_peer'],
                               attestation=found['attestation'], broker_binding=found.get('payments'))
                elif now >= node['readiness_deadline'] and not node.get('readiness_failed'):
                    node['readiness_failed'] = True
                    self.event('readiness_timeout', slot_id=slot['slot_id'], run=str(node['path']),
                               error='new node did not attest at broker; waiting for this owned guest to finish')
        if not self.stopping and (not self.args.cycles or self.launched < self.args.cycles):
            for slot in self.slots:
                active = [n for n in self.active if n['slot_id'] == slot['slot_id']]
                # Resolve one boot's broker identity before launching another, so
                # identically measured guests cannot be assigned to the wrong slot.
                if any(n['node'] is None and not n.get('readiness_failed') for n in self.active):
                    break
                if (not slot['stopped'] and now >= slot.get('retry_at', 0) and len(active) < 2 and not any(n['node'] is None for n in active)
                        and (slot['retry_pending'] or should_replace(active, now, self.args.replace_after))):
                    try:
                        if self.args.pool_root:
                            lock = (self.args.pool_root/'boot.lock').open('a')
                            try:
                                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            except BlockingIOError:
                                lock.close()
                                break
                            self.boot_lock = lock
                        self.launch(slot)
                    except MacOccupied:
                        self.event('waiting_for_other_lane', slot_id=slot['slot_id'])
                    except BrokerUnavailable:
                        self.retry_broker(slot, self.last_broker_error)
                    break

    def snapshot(self):
        now = time.monotonic()
        slots = []
        for slot in self.slots:
            active = [n for n in self.active if n['slot_id'] == slot['slot_id']]
            for node in active or [None]:
                registered = node['node'] if node else None
                state = 'failed' if slot['stopped'] else 'launching'
                if node:
                    if node.get('readiness_failed'):
                        state = 'failed'
                    elif registered:
                        # A registered replacement takes the slot; the predecessor only finishes a stay it holds.
                        replaced = any(n['node'] and n['started'] > node['started'] for n in active)
                        state = ('draining' if now >= node['started'] + node['admit_seconds']
                                 else 'busy' if registered.get('telemetry', {}).get('busy')
                                 else 'draining' if replaced else 'ready')
                    elif (node['path']/'out/console-v3.log').exists():
                        state = 'attesting'
                slots.append({'slot_id': slot['slot_id'], 'state': state,
                              'relay_peer': registered['relay_peer'] if registered else None,
                              'run_id': (registered.get('payments', {}).get('runId') or registered.get('attestation', {}).get('run')) if registered else None,
                              'node_id': self.payments['node'],
                              'started_at': node['started_at'] if node else None,
                              'jobs_served': slot['jobs_served'] + sum((n['node'] or {}).get('telemetry', {}).get('jobs_served', 0) for n in active),
                              'last_error': json.dumps(slot['last_error'], ensure_ascii=False) if slot['last_error'] else None,
                              'attestation': registered})
        return {'classes': [self.payments['node']], 'config': self.config, 'hardware': self.hardware, 'slots': slots, 'errors': self.errors}

    def run(self):
        self.args.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.event('capacity', config=self.config, hardware=self.hardware)
        while True:
            self.tick()
            snapshot = self.snapshot()
            temporary = self.args.state/'directory.tmp'
            temporary.write_text(json.dumps(snapshot))
            temporary.replace(self.args.state/'directory.json')
            if self.publisher:
                record = self.publisher.tick(snapshot)
                if record:
                    name = record.pop('event')
                    if name == 'heartbeat_error':
                        self.remember_error({'at': int(time.time()), 'slot_id': None, 'stage': 'heartbeat', **record})
                    self.event(name, **record)
            if not self.active and (self.stopping or all(s['stopped'] for s in self.slots) or (self.args.cycles and self.launched >= self.args.cycles)):
                if self.boot_lock:
                    self.boot_lock.close()
                break
            time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator', type=Path, default=Path.home()/'.dsmack/operator.json')
    parser.add_argument('--max-slots', type=int, help='cap the operator guest slots for this pool')
    parser.add_argument('--coexist-pool', type=Path, action='append', default=[], help='allow guests owned by launcher state anywhere beneath this directory')
    parser.add_argument('--publisher-key', type=Path)
    parser.add_argument('--publisher-address')
    parser.add_argument('--pool-version', help='source commit used by this staged pool')
    parser.add_argument('--runner', required=True, type=Path)
    parser.add_argument('--workload', required=True, type=Path)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--adopt-state', type=Path, help='frozen legacy pool state transferred by the launcher')
    parser.add_argument('--pool-root', type=Path, help='launcher-owned generations sharing transports and a boot lock')
    parser.add_argument('--repo', type=Path, default=HERE.parents[1])
    parser.add_argument('--broker', required=True)
    parser.add_argument('--debugfs', type=Path, default=Path('/opt/homebrew/opt/e2fsprogs/sbin/debugfs'),
                        help='read-only result diagnostic extractor')
    parser.add_argument('--seconds', type=int, default=3600)
    parser.add_argument('--drain-seconds', type=int, default=480)
    parser.add_argument('--replace-after', type=int, default=None)
    parser.add_argument('--readiness-timeout', type=int, default=90)
    parser.add_argument('--cycles', type=int, default=0, help='0 rotates continuously')
    args = parser.parse_args()
    if args.replace_after is None:
        args.replace_after = args.seconds//2 + 30
    if bool(args.publisher_key) != bool(args.publisher_address):
        parser.error('--publisher-key and --publisher-address are required together')
    if args.publisher_key and not args.pool_version:
        parser.error('--pool-version is required for published heartbeats')
    if (not 1 <= args.seconds <= 3600 or not 1 <= args.drain_seconds < args.seconds
            or not 1 <= args.replace_after < args.seconds
            or max(args.replace_after, args.seconds-args.replace_after) + args.readiness_timeout >= args.seconds-args.drain_seconds):
        parser.error('two-slot replacement must attest before admission closes, lifetime <=3600s')
    args.runner, args.workload, args.state, args.repo = [p.resolve() for p in (args.runner, args.workload, args.state, args.repo)]
    manifest = validate_config(args.runner, args.workload, operator_config(args.operator, hardware(), args.max_slots))
    measured = json.loads(manifest['docker_compose_file'])['services']['node']
    if int(measured['command'][2]) != args.seconds or int(measured['environment']['ADMIT_SECONDS']) != args.seconds-args.drain_seconds:
        parser.error('pool lifetime and admission must match measured compose')
    if not args.debugfs.is_file() or not os.access(args.debugfs, os.X_OK):
        parser.error('--debugfs must name an executable result extractor')
    pool = Pool(args)
    if args.adopt_state:
        from pool_handoff import inherited_guests
        pool.active = inherited_guests(args.adopt_state)
        pool.launched = len(pool.active)
        (args.state/'adopted.json').write_text(json.dumps(dict(drivers=[n['process'].pid for n in pool.active])))
    signal.signal(signal.SIGTERM, lambda *_: setattr(pool, 'stopping', True))
    signal.signal(signal.SIGINT, lambda *_: setattr(pool, 'stopping', True))
    pool.run()


if __name__ == '__main__':
    main()
