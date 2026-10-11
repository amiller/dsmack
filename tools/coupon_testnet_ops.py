#!/usr/bin/env python3
"""Pinned SSH/Docker adapter for the private public-testnet controller.

No provisioning, CLAIM, provider-key creation, chain transaction or policy epoch
change exists here. Renewal rotates only the same approval's owner JWT. A paused
idle barrier prevents CLAIM racing the inspected Store before the stopped backup.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.coupon_owner_session import Refused, atomic_json, jwt_exp, private_dir, private_json
from tools.coupon_staging_authority import load_authority, sign
from experiments.coupon_redemption.staging_approval import approval, configuration, CONFIG_DOMAIN
from experiments.coupon_redemption.issuance_guard import GuardRPC, BASE_RPC, BASE_PROFILE, keccak

FIELDS = {'version', 'ssh_config', 'ssh_target', 'container', 'image_digest', 'volume',
          'mount_path', 'approval_file', 'config_file', 'authority_dir', 'approval_public_key',
          'owner_dir', 'state_dir', 'probe_script', 'probe_script_sha256', 'public_bundle'}

# This executes inside the pinned image/volume and returns hashes/counts only.
# Hashes include all user obligations and journal rows, never print their values.
METADATA = r'''import sqlite3,json,hashlib,base64,sys
p=sys.argv[1];d=sqlite3.connect('file:'+p+'/state/state.sqlite?mode=ro',uri=True)
tables=[r[0]for r in d.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
h=hashlib.sha256()
for table in tables:
 rows=d.execute('SELECT * FROM "'+table.replace('"','""')+'"').fetchall()
 enc=lambda row:json.dumps([{'bytes':v.hex()}if isinstance(v,bytes)else v for v in row],sort_keys=True,separators=(',',':'))
 h.update(json.dumps([table,sorted(enc(row)for row in rows)],separators=(',',':')).encode())
c=json.load(open(p+'/config.json'))['payload'];a=json.load(open(p+'/approval.json'))['payload']
exp=json.loads(base64.urlsafe_b64decode(c['provider']['session_jwt'].split('.')[1]+'==='))['exp']
print(json.dumps({'issuing_jobs':d.execute("SELECT COUNT(*)FROM coupons WHERE state='issuing'").fetchone()[0],'obligation_fingerprint':h.hexdigest(),'owner_expires_at_unix':exp,'approval_expires_at_unix':int(__import__('datetime').datetime.fromisoformat(a['expires_at'].replace('Z','+00:00')).timestamp())}))'''


def plan(path):
    value = private_json(path)
    if type(value) is not dict or set(value) != FIELDS or type(value['version']) is not int or value['version'] != 1:
        raise Refused('adapter_plan')
    for key in ('container', 'volume', 'ssh_target'):
        if not isinstance(value[key], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value[key]):
            raise Refused('identifier')
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_digest'])
            or not re.fullmatch(r'[0-9a-f]{64}', value['approval_public_key'])
            or not re.fullmatch(r'[0-9a-f]{64}', value['probe_script_sha256'])
            or not re.fullmatch(r'/[A-Za-z0-9_/-]+', value['mount_path'])
            or '..' in value['mount_path'].split('/')):
        raise Refused('pins')
    for key in ('authority_dir', 'owner_dir', 'state_dir'): private_dir(value[key])
    for key in ('ssh_config', 'approval_file', 'config_file'): protected_bytes(value[key])
    for key in ('probe_script', 'public_bundle'):
        if not Path(value[key]).is_absolute(): raise Refused('public_path')
    if hashlib.sha256(Path(value['probe_script']).read_bytes()).hexdigest() != value['probe_script_sha256']:
        raise Refused('probe_pin')
    approved = approval(protected_bytes(value['approval_file']), bytes.fromhex(value['approval_public_key']))
    configuration(protected_bytes(value['config_file']), bytes.fromhex(value['approval_public_key']), approved)
    return value


def protected_bytes(path, limit=65536, *, allow_empty=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or st.st_nlink != 1): raise Refused('private_file')
        with os.fdopen(fd, 'rb', closefd=False) as f: result = f.read(limit + 1)
        if len(result) > limit or (not result and not allow_empty): raise Refused('size')
        return result
    finally: os.close(fd)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())


class Ops:
    def __init__(self, value):
        self.value = value
        self.ssh = ['ssh', '-F', value['ssh_config'], '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15', value['ssh_target']]

    def remote(self, args, *, timeout=60):
        result = subprocess.run(self.ssh + [shlex.join(args)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        if result.returncode != 0 or len(result.stdout) > 1048576: raise Refused('remote')
        return result.stdout

    def inspect_container(self, *, paused=False):
        value = json.loads(self.remote(['docker', 'inspect', self.value['container']]))
        if len(value) != 1: raise Refused('container')
        item = value[0]
        if (item['Image'] != self.value['image_digest'] or not item['State']['Running']
                or item['State']['Paused'] is not paused
                or item['HostConfig']['LogConfig']['Type'] != 'none'
                or not any(m.get('Name') == self.value['volume'] and m['Destination'] == self.value['mount_path']
                           for m in item['Mounts'])):
            raise Refused('container_pins')
        rows = self.remote(['docker', 'top', self.value['container'], '-eo', 'pid,comm']).decode().splitlines()
        # A forked issuer/HTTPS/checker makes more rows; do not interrupt it.
        idle = [r.split()[-1] for r in rows] == ['COMMAND', 'MainThread', 'python-worker']
        return idle

    def metadata(self, *, paused=False):
        if paused:
            cmd = ['docker', 'run', '--rm', '--network', 'none', '--log-driver', 'none',
                '--user', '1000:1000', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '-v', self.value['volume'] + ':' + self.value['mount_path'] + ':ro',
                '--entrypoint', 'python3', self.value['image_digest'], '-c', METADATA, self.value['mount_path']]
        else:
            cmd = ['docker', 'exec', self.value['container'], 'python3', '-c', METADATA, self.value['mount_path']]
        return json.loads(self.remote(cmd))

    def inspect(self):
        idle = self.inspect_container()
        result = self.metadata()
        config = json.loads(protected_bytes(self.value['config_file']))['payload']
        profile = config['finality_profile']
        if profile['trust_profile'] != BASE_PROFILE or profile['execution_rpc'] != BASE_RPC:
            raise Refused('reserve_profile')
        rpc = GuardRPC(BASE_RPC)
        if rpc.call('eth_chainId', []) != '0x2105': raise Refused('chain')
        quantity = lambda raw: int(raw, 16) if isinstance(raw, str) and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]*)', raw) else (_ for _ in ()).throw(Refused('quantity'))
        price = quantity(rpc.call('eth_gasPrice', []))
        balance = quantity(rpc.call('eth_getBalance', [profile['issuer_address'], 'latest']))
        def oracle(signature, units):
            data = '0x' + (keccak(signature.encode())[:4] + units.to_bytes(32, 'big')).hex()
            raw = rpc.call('eth_call', [{'to': '0x420000000000000000000000000000000000000f', 'data': data}, 'latest'])
            if not isinstance(raw, str) or not re.fullmatch(r'0x[0-9a-f]{64}', raw): raise Refused('fee')
            return int(raw, 16)
        # Existing measured sender uses a fixed 150k limit. The 300-byte L1
        # upper bound and doubled L1 allowance match the reviewed trial budget.
        required = 150000 * config['gas_price_wei'] + 2 * oracle('getL1FeeUpperBound(uint256)', 300) + oracle('getOperatorFee(uint256)', 150000)
        ready = price <= config['gas_price_wei'] and balance >= required
        result.update(ready=True, one_claim_reserve_ready=ready)
        if not idle: result['issuing_jobs'] = max(1, result['issuing_jobs'])
        return result

    def hold(self, channel):
        channel = private_dir(channel)
        pipe = os.open(channel / 'input', os.O_RDWR | os.O_NOFOLLOW)
        if not stat.S_ISFIFO(os.fstat(pipe).st_mode): raise Refused('fifo')
        out = os.open(channel / 'output.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        child = subprocess.Popen(self.ssh + [shlex.join(['docker', 'attach', '--sig-proxy=false', self.value['container']])],
            stdin=pipe, stdout=out, stderr=subprocess.DEVNULL)
        atomic_json(channel / 'holder.json', {'pid': os.getpid(), 'child_pid': child.pid})
        return child.wait()

    def rotate(self):
        base = private_dir(self.value['state_dir'])
        state = Path(tempfile.mkdtemp(prefix='rotation-', dir=base))
        # An adapter interruption has its own exclusive marker. Do not repeat a
        # pause/kill/start/readmit sequence merely because a supervisor restarts.
        write_new(state / 'rotate-started', b'rotation started; reconcile on failure\n')
        if not self.inspect_container(): raise Refused('busy')
        before = self.metadata()
        if before['issuing_jobs'] != 0: raise Refused('busy')
        key, public = load_authority(Path(self.value['authority_dir']))
        if public != self.value['approval_public_key']: raise Refused('authority')
        approved = approval(protected_bytes(self.value['approval_file']), bytes.fromhex(public))
        old_config = json.loads(protected_bytes(self.value['config_file']))['payload']
        changed = json.loads(json.dumps(old_config))
        changed['provider']['session_jwt'] = private_json(Path(self.value['owner_dir']) / 'owner-session.json')['session_jwt']
        new_raw = sign(changed, CONFIG_DOMAIN, key)
        configuration(new_raw, bytes.fromhex(public), approved)
        write_new(state / 'next-config.json', new_raw)
        # Freeze first, then prove idle+Store. A CLAIM arriving after the earlier
        # check must be detected before any termination or state copy.
        self.remote(['docker', 'pause', self.value['container']])
        try:
            if not self.inspect_container(paused=True): raise Refused('busy_barrier')
            frozen = self.metadata(paused=True)
            if frozen['issuing_jobs'] != 0 or frozen['obligation_fingerprint'] != before['obligation_fingerprint']:
                raise Refused('state_race')
        except Exception:
            self.remote(['docker', 'unpause', self.value['container']])
            raise
        backup = state / 'stopped-volume-backup.tar'
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output:
                proc = subprocess.run(self.ssh + [shlex.join(['docker', 'run', '--rm', '--network', 'none',
                    '--log-driver', 'none', '--user', '1000:1000', '--read-only', '-v', self.value['volume'] + ':/backup:ro',
                    '--entrypoint', 'tar', self.value['image_digest'], '-cf', '-', '-C', '/backup', '.'])],
                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, timeout=120)
                output.flush(); os.fsync(output.fileno())
            if proc.returncode != 0: raise Refused('backup')
        except Exception:
            self.remote(['docker', 'unpause', self.value['container']])
            raise
        # SIGKILL while paused closes the idle barrier without a new-CLAIM race.
        # SQLite+WAL+SHM and all state were copied first. No claim job is killed.
        self.remote(['docker', 'kill', self.value['container']])
        item = json.loads(self.remote(['docker', 'inspect', self.value['container']]))[0]
        if item['State']['Running']: raise Refused('not_stopped')
        channel = state / 'channel'
        channel.mkdir(mode=0o700)
        os.mkfifo(channel / 'input', 0o600)
        self.remote(['docker', 'start', self.value['container']])
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'hold', '--plan', self.value['_plan_path'], '--channel', str(channel)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        end = time.monotonic() + 15
        while not (channel / 'holder.json').exists():
            if time.monotonic() >= end: raise Refused('holder')
            time.sleep(.1)
        fd = os.open(channel / 'input', os.O_WRONLY | os.O_NOFOLLOW)
        try:
            for frame in (protected_bytes(self.value['approval_file']), new_raw):
                raw = frame.strip() + b'\n'; cursor = 0
                while cursor < len(raw): cursor += os.write(fd, raw[cursor:])
        finally: os.close(fd)
        end = time.monotonic() + 120
        while time.monotonic() < end:
            try: raw = protected_bytes(channel / 'output.jsonl', limit=1048576, allow_empty=True)
            except FileNotFoundError:
                time.sleep(.25); continue
            for line in raw.splitlines():
                try: item = json.loads(line)
                except ValueError: continue
                if item.get('ready') is True:
                    if (item.get('private_issuance_qualified') is not False or item.get('rollback_qualified') is not False
                            or item.get('environment') != 'private-debug-staging'):
                        raise Refused('readiness')
                    after = self.metadata()
                    if after['obligation_fingerprint'] != before['obligation_fingerprint']: raise Refused('retention')
                    # Replace the local signed config only after live admission.
                    atomic_json(self.value['config_file'], json.loads(new_raw))
                    return {'rotated': True, 'before_fingerprint': before['obligation_fingerprint'],
                            'after_fingerprint': after['obligation_fingerprint']}
            time.sleep(.25)
        raise Refused('admission_timeout')

    def verify(self):
        result = self.inspect()
        process = subprocess.run(['node', self.value['probe_script'], self.value['public_bundle']],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90)
        if process.returncode != 0 or len(process.stdout) > 65536: raise Refused('probe')
        report = json.loads(process.stdout)
        if (report.get('publicPeerRouteVerified') is not True or report.get('approvalMatchesFreshIssuer') is not True
                or report.get('giftRead') is not False or report.get('bearerSent') is not False
                or report.get('providerEffects') != 0): raise Refused('probe')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inspect', 'rotate', 'verify', 'hold'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--channel', help='private holder channel, only for hold')
    args = parser.parse_args(); os.umask(0o077)
    try:
        value = plan(args.plan); value['_plan_path'] = args.plan
        if args.operation == 'hold':
            if not args.channel: raise Refused('channel')
            result = Ops(value).hold(args.channel)
        else:
            if args.channel: raise Refused('channel')
            result = getattr(Ops(value), args.operation)()
        if args.operation == 'hold': raise SystemExit(result)
    except Exception:
        parser.exit(2, 'Private operation refused; no input content printed.\n')
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__': main()
