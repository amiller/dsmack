"""Transfer a legacy launcher's owned processes without stopping its guests."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time


class ExistingProcess:
    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        result = subprocess.run(['ps', '-p', str(self.pid), '-o', 'stat='], capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
            raise RuntimeError('owned process probe failed: '+str(self.pid))
        self.returncode = 0 if result.returncode or result.stdout.strip().startswith('Z') else None
        return self.returncode

    def send_signal(self, sig):
        os.kill(self.pid, sig)

    def freeze(self):
        self.send_signal(signal.SIGSTOP)
        deadline = time.monotonic()+5
        while True:
            state = subprocess.check_output(['ps', '-p', str(self.pid), '-o', 'stat='], text=True).strip()
            if state.startswith('T'):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('controller did not stop for ownership transfer')
            time.sleep(.01)

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def wait(self, timeout):
        deadline = time.monotonic()+timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(['pid', str(self.pid)], timeout)
            time.sleep(.1)
        return self.returncode


def inherited_guests(state):
    """Replay only active attempts; guest results still decide success at retirement."""
    attempts = {}
    for line in (state/'pool.jsonl').read_text().splitlines():
        event = json.loads(line)
        if event['event'] == 'launch':
            attempts[event['run']] = dict(event)
        elif event['event'] == 'ready' and event['run'] in attempts:
            attempts[event['run']]['relay_peer'] = event['relay_peer']
        elif event['event'] in ('guest_failed', 'retired'):
            attempts.pop(event['run'], None)
    snapshot = json.loads((state/'directory.json').read_bytes())
    by_peer = {s['relay_peer']: s for s in snapshot['slots'] if s['attestation']}
    active = []
    for attempt in attempts.values():
        if attempt.get('relay_peer') not in by_peer:
            raise RuntimeError('legacy guest is still booting; retry handoff after attestation')
        slot = by_peer[attempt['relay_peer']]
        path = Path(attempt['run'])
        pid = attempt['driver_pid']
        command = subprocess.check_output(['ps', '-ww', '-p', str(pid), '-o', 'command='], text=True)
        if str(path) not in shlex.split(command) or 'pool_mac_run.py' not in command:
            raise RuntimeError('legacy driver identity differs from its launch record')
        manifest = json.loads((path/'compose-manifest.json').read_bytes())
        node = json.loads(manifest['docker_compose_file'])['services']['node']
        started_at = slot['started_at']
        active.append(dict(slot_id=slot['slot_id'], started_at=started_at,
            started=time.monotonic()-(time.time()-started_at), path=path, process=ExistingProcess(pid),
            # Launches recorded before key tracking name no kid; their outcome is not counted against a key.
            kid=attempt.get('kid'),
            node=slot['attestation'], previous=set(), admit_seconds=int(node['environment']['ADMIT_SECONDS'])))
    if not active:
        raise RuntimeError('legacy handoff needs an attested serving guest')
    return active


class LegacyHandoff:
    def __init__(self, pid, state):
        command = subprocess.check_output(['ps', '-ww', '-p', str(pid), '-o', 'command='], text=True)
        words = shlex.split(command)
        if 'mac-pool.py' not in command or '--state' not in words or Path(words[words.index('--state')+1]).resolve() != state.resolve():
            raise ValueError('--adopt-launcher must own the supplied --state')
        self.launcher = ExistingProcess(pid)
        self.pool = None
        self.committed = False
        self.transports = []
        try:
            self.launcher.freeze()
            rows = subprocess.check_output(['ps', '-ww', '-axo', 'pid=,ppid=,pgid=,command='], text=True)
            for row in rows.splitlines():
                child, parent, group, command = row.strip().split(None, 3)
                if int(parent) != pid:
                    continue
                proc = ExistingProcess(int(child))
                if Path(shlex.split(command)[1]).name == 'pool.py':
                    if self.pool:
                        raise RuntimeError('legacy launcher has multiple pools')
                    self.pool = proc
                    proc.freeze()
                elif int(group) == int(child):
                    self.transports.append(proc)
                else:
                    raise RuntimeError('unexpected legacy launcher child: '+child)
            if not self.pool or not self.transports:
                raise RuntimeError('legacy launcher lacks its pool or transports')
            inherited_guests(state/'guests')  # Refuse an ambiguous in-progress boot.
        except BaseException:
            self.resume()
            raise

    def commit(self):
        # New pool has acknowledged ownership. SIGKILL affects only these two
        # frozen controllers; VM drivers and transport groups keep running.
        self.launcher.send_signal(signal.SIGKILL)
        self.pool.send_signal(signal.SIGKILL)
        self.committed = True

    def resume(self):
        if not self.committed:
            if self.pool:
                self.pool.send_signal(signal.SIGCONT)
            self.launcher.send_signal(signal.SIGCONT)
