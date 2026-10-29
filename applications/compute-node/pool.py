#!/usr/bin/env python3
"""Keep a verified compute node warm; run locally on the operator Mac."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import runpy
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


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def ready_node(nodes, previous, measurement, image):
    return next((n for n in nodes if n['relay_peer'] not in previous and n.get('kind') == 'compute'
                 and n.get('manifest_sha256') == measurement and n.get('os_image_hash') == image
                 and n.get('attestation', {}).get('status') == 'verified'), None)


def should_replace(active, now, replace_after):
    serving = [n for n in active if n.get('node') and now < n['started'] + n['admit_seconds']]
    return not serving or now - max(n['started'] for n in serving) >= replace_after


def preflight(state, active):
    free = shutil.disk_usage(state).free
    if free < 12 * (1 << 30):
        raise RuntimeError('less than 12 GiB free on Mac')
    result = subprocess.run(['pgrep', '-fl', 'MacOS/dsmack-runner'], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError('Mac runner process probe failed')
    owned_sessions = {str(n['path']/'session.json') for n in active}
    for line in result.stdout.splitlines():
        pid = int(line.split()[0])
        command = subprocess.check_output(['ps', '-p', str(pid), '-o', 'command='], text=True)
        if not owned_sessions.intersection(shlex.split(command)):
            raise MacOccupied('another lane owns the active Mac VM; waiting')
    return {'free_bytes': free, 'owned_runner_sessions': sorted(owned_sessions)}


def guest_closed(run):
    lines = (run/'out/console-v3.log').read_text(errors='replace').splitlines()
    return ('DSMACK_SUPERVISOR_DONE runner_failures=0' in lines
            and any(line.startswith('DSMACK_RESULT_CLOSED_V1 ') for line in lines))


def preserve_and_retire(run, repo):
    """Keep original evidence before removing the exact stopped attempt's disks."""
    helper = json.loads((run/'helper-stopped.json').read_bytes())
    try:
        os.kill(helper['pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise RuntimeError('owned network helper remains active')
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
        self.active = []
        self.launched = 0
        self.stopping = False
        self.failure = None
        self.manifest = args.workload/'compose-manifest.json'
        self.measurement = sha(self.manifest)
        self.image = json.loads(self.manifest.read_bytes())['base_vm']['os_image_hash']
        self.started = time.monotonic()

    def event(self, name, **fields):
        record = {'event': name, 'elapsed_seconds': round(time.monotonic()-self.started, 3), **fields}
        print(json.dumps(record), flush=True)
        with (self.args.state/'pool.jsonl').open('a') as log:
            log.write(json.dumps(record)+'\n')

    def nodes(self):
        try:
            with urlopen(self.args.broker.rstrip('/')+'/nodes', timeout=20) as response:
                return json.load(response)
        except (HTTPError, URLError, TimeoutError) as error:
            self.event('broker_unavailable', error=type(error).__name__, status=getattr(error, 'code', None))
            return None

    def launch(self):
        check = preflight(self.args.state, self.active)
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
                                 str(self.args.seconds)], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        self.launched += 1
        node = {'process': proc, 'path': run, 'started': time.monotonic(), 'node': None, 'previous': baseline,
                'admit_seconds': self.args.seconds-self.args.drain_seconds, 'readiness_deadline': time.monotonic()+self.args.readiness_timeout}
        self.active.append(node)
        self.event('launch', run=str(run), driver_pid=proc.pid)

    def tick(self):
        now = time.monotonic()
        for node in self.active[:]:
            proc = node['process']
            if proc.poll() is not None:
                # Failed/uncertain runs deliberately retain their disks and stop
                # rotation until the operator has their missing evidence.
                if proc.returncode:
                    raise RuntimeError('owned VM driver failed; attempt retained at '+str(node['path']))
                if node['node'] is None or not guest_closed(node['path']):
                    evidence = preserve_and_retire(node['path'], self.args.repo)
                    self.stopping = True
                    self.failure = 'guest failed before verified result closure; evidence at '+str(node['path']/'evidence')
                    self.event('guest_failed', run=str(node['path']), **evidence)
                else:
                    cleanup = preserve_and_retire(node['path'], self.args.repo)
                    self.event('retired', run=str(node['path']), **cleanup)
                self.active.remove(node)
                continue
            if node['node'] is None:
                nodes = self.nodes()
                if nodes is None:
                    node['readiness_deadline'] = now + self.args.readiness_timeout
                    continue
                found = ready_node(nodes, node['previous'], self.measurement, self.image)
                if found:
                    node['node'] = found
                    self.event('ready', run=str(node['path']), relay_peer=found['relay_peer'],
                               attestation=found['attestation'], broker_binding=found.get('payments'))
                elif now >= node['readiness_deadline']:
                    raise RuntimeError('new node did not attest at broker; running attempt retained at '+str(node['path']))
        if not self.stopping and (not self.args.cycles or self.launched < self.args.cycles):
            # At most one replacement boots alongside one serving/draining node.
            if len(self.active) < 2 and not any(n['node'] is None for n in self.active) and should_replace(self.active, now, self.args.replace_after):
                try:
                    self.launch()
                except MacOccupied:
                    self.event('waiting_for_other_lane')
                except BrokerUnavailable:
                    self.event('waiting_for_broker')

    def run(self):
        self.args.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        while True:
            self.tick()
            if not self.active and (self.stopping or (self.args.cycles and self.launched >= self.args.cycles)):
                break
            time.sleep(2)
        if self.failure:
            raise RuntimeError(self.failure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', required=True, type=Path)
    parser.add_argument('--workload', required=True, type=Path)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--repo', type=Path, default=HERE.parents[1])
    parser.add_argument('--broker', required=True)
    parser.add_argument('--seconds', type=int, default=840)
    parser.add_argument('--drain-seconds', type=int, default=270)
    parser.add_argument('--replace-after', type=int, default=450)
    parser.add_argument('--readiness-timeout', type=int, default=90)
    parser.add_argument('--cycles', type=int, default=0, help='0 rotates continuously')
    args = parser.parse_args()
    if (not 1 <= args.seconds <= 840 or not 1 <= args.drain_seconds < args.seconds
            or not 1 <= args.replace_after < args.seconds
            or max(args.replace_after, args.seconds-args.replace_after) + args.readiness_timeout >= args.seconds-args.drain_seconds):
        parser.error('two-slot replacement must attest before admission closes, lifetime <=840s')
    args.runner, args.workload, args.state, args.repo = [p.resolve() for p in (args.runner, args.workload, args.state, args.repo)]
    measured = json.loads(json.loads((args.workload/'compose-manifest.json').read_bytes())['docker_compose_file'])['services']['node']
    if int(measured['command'][2]) != args.seconds or int(measured['environment']['ADMIT_SECONDS']) != args.seconds-args.drain_seconds:
        parser.error('pool lifetime and admission must match measured compose')
    pool = Pool(args)
    signal.signal(signal.SIGTERM, lambda *_: setattr(pool, 'stopping', True))
    signal.signal(signal.SIGINT, lambda *_: setattr(pool, 'stopping', True))
    pool.run()


if __name__ == '__main__':
    main()
