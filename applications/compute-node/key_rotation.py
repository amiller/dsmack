#!/usr/bin/env python3
"""Replace a dead App Attest key without changing the signed runner.

The pool (pool.py --key-rotation CONFIG) counts signing failures per key. After two in a row on the same
key it marks the key suspect, stops launching with it and starts `rotate` once. `rotate` then:
  probe    runs one short hvf-v3 with the current key and one with a fresh throwaway key. Only if the current
           key still fails while the throwaway key signs is the key marked dead; otherwise the suspicion is
           cleared and the pool launches with it again
  enroll   runs the runner's own `enroll` command into a new dir with a fresh challenge
  sign/send/confirm  submits AppleAttestRegistry enroll(leaf, authData, clientData, intermediateId) from the
           Mac's gas wallet and checks keys(kid) through layover-chain (Helios-verified)
  link     has the provisioner sign MacLink(kid, publisher, operator, nonce+1) and posts it (dsmack link)
  switch   moves runner/enrollment aside (kept as enrollment.dead-*) and puts the new one in its place;
           follower runners (the line loops) link to runner/enrollment and pick it up at their next launch
  restart  restarts the pool service, unless the pool's workload manifest still pins another key id: then
           the running generation stays up (it refuses launches with a key its manifest does not pin) and
           rotate ends with that error; `resume` restarts once the pin is gone
Each finished step is recorded in STATE/rotation-<dead kid>/progress.json; `resume` continues from there.
A reverted enroll transaction ends the rotation; the error names the recovery: fix the cause, move
STATE/rotation-<dead kid> aside and run `rotate` again, which enrolls another fresh key.

  key_rotation.py check --config C              dry run: every precondition, no writes
  key_rotation.py rotate --config C --dead-kid 0x...
  key_rotation.py resume --config C --dead-kid 0x...
  key_rotation.py dead-clear --config C --kid 0x...   forget a key's failures, suspicion or death
  key_rotation.py new-gas-wallet PATH
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

HERE = Path(__file__).resolve().parent
SIGN_FAILURES = ('com.apple.devicecheck.error', 'e007c013')
ENROLL = keccak(text='enroll(bytes,bytes,bytes,bytes32)')[:4]
KEYS = keccak(text='keys(bytes32)')[:4]


class KeyUnusable(RuntimeError):
    pass


def log(step, **fields):
    print(json.dumps({'at': int(time.time()), 'step': step, **fields}), flush=True)


def write_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2))
    tmp.replace(path)


def kid_of(enrollment):
    return '0x' + base64.b64decode((enrollment/'keyId.txt').read_text().strip(), validate=True).hex()


def key_failure(run, last_error):
    stderr = run/'stderr.txt'
    text = json.dumps(last_error) + (stderr.read_text(errors='replace') if stderr.exists() else '')
    return any(s in text for s in SIGN_FAILURES)


class KeyWatch:
    """Per-key consecutive signing failures, shared by every pool generation through STATE/keys.json."""
    def __init__(self, config_path):
        self.config_path = config_path
        self.state = Path(json.loads(config_path.read_bytes())['state'])
        self.state.mkdir(parents=True, exist_ok=True)
        self.file = self.state/'keys.json'

    def keys(self):
        return json.loads(self.file.read_bytes()) if self.file.exists() else {}

    def require_live(self, kid):
        entry = self.keys().get(kid, {})
        if entry.get('dead_at') or entry.get('suspect_at'):
            raise KeyUnusable('%s is %s' % (kid, 'dead' if entry.get('dead_at') else 'suspect, being probed'))

    def observe(self, kid, failed):
        """True exactly when this observation makes the key suspect: its second signing failure in a row."""
        keys = self.keys()
        entry = keys.setdefault(kid, {'failures': 0})
        if entry.get('dead_at') or entry.get('suspect_at'):
            return False
        entry['failures'] = entry['failures'] + 1 if failed else 0
        if entry['failures'] >= 2:
            entry['suspect_at'] = int(time.time())
        write_json(self.file, keys)
        return 'suspect_at' in entry

    def set(self, kid, **fields):
        keys = self.keys()
        keys[kid] = fields
        write_json(self.file, keys)

    def clear(self, kid):
        keys = self.keys()
        keys.pop(kid, None)
        write_json(self.file, keys)

    def rotate(self, kid):
        log_path = self.state/('rotation-' + kid[2:10] + '.log')
        with log_path.open('a') as out:
            subprocess.Popen([sys.executable, str(HERE/'key_rotation.py'), 'rotate', '--config', str(self.config_path),
                              '--dead-kid', kid], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                             start_new_session=True)
        return log_path


def cbor(b, i=0):
    """The CBOR subset an App Attest attestation uses: unsigned ints, byte/text strings, arrays, maps."""
    major, info = b[i] >> 5, b[i] & 31
    i += 1
    if info < 24:
        n = info
    elif info <= 27:
        k = 1 << (info - 24)
        n, i = int.from_bytes(b[i:i+k], 'big'), i + k
    else:
        raise ValueError('unsupported CBOR length')
    if major == 0:
        return n, i
    if major in (2, 3):
        return (b[i:i+n].decode() if major == 3 else b[i:i+n]), i + n
    out = [] if major == 4 else {} if major == 5 else None
    if out is None:
        raise ValueError('unsupported CBOR major type %d' % major)
    for _ in range(n):
        v, i = cbor(b, i)
        if major == 4:
            out.append(v)
        else:
            out[v], i = cbor(b, i)
    return out, i


def enroll_call(enrollment, config):
    raw = (enrollment/'attestation.cbor').read_bytes()
    att, end = cbor(raw)
    if end != len(raw):
        raise ValueError('attestation.cbor has trailing bytes')
    x5c, auth = att['attStmt']['x5c'], att['authData']
    if hashlib.sha256(x5c[1]).hexdigest() != config['intermediate_sha256']:
        raise ValueError('Apple intermediate sha256 %s is not the configured one; endorse it on chain and update '
                         'intermediate_id/intermediate_sha256' % hashlib.sha256(x5c[1]).hexdigest())
    kid = kid_of(enrollment)
    if auth[55:55 + int.from_bytes(auth[53:55], 'big')].hex() != kid[2:]:
        raise ValueError('authData credential id differs from keyId.txt')
    data = ENROLL + encode(['bytes', 'bytes', 'bytes', 'bytes32'],
                           [x5c[0], auth, (enrollment/'clientData.bin').read_bytes(), bytes.fromhex(config['intermediate_id'][2:])])
    return kid, '0x' + data.hex()


def get_json(url, body=None):
    request = Request(url, data=None if body is None else json.dumps(body).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'dsmack-key-rotation'})
    try:
        with urlopen(request, timeout=60) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError('%s: HTTP %d %s' % (url, error.code, error.read(4096).decode(errors='replace'))) from None


def chain(config, path, **query):
    """A Helios-verified read through layover-chain; anything unverified, including a revert, raises."""
    answer = get_json(config['chain_read'].rstrip('/') + path + '?' + urlencode(query))
    if answer.get('verified_by') != 'helios-opstack':
        raise RuntimeError('layover-chain %s: %s' % (path, answer.get('error', answer)))
    return answer


def key(config, kid):
    words = bytes.fromhex(chain(config, '/call', to=config['registry'], data='0x' + (KEYS.hex() + kid[2:]))['result'][2:])
    return {'expires': int.from_bytes(words[64:96], 'big'), 'enrolled': words[159] == 1}


def rpc(config, method, *params):
    answer = get_json(config['rpc'], {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)})
    if 'error' in answer:
        raise RuntimeError('%s: %s' % (method, answer['error']))
    return answer['result']


def broker_link(config, publisher, kid):
    state = get_json(config['broker'].rstrip('/') + '/fleet/ownership?' + urlencode({'publisher': publisher, 'kid': kid}))
    return state, next((l['link'] for l in state['links'] if l['link']['kid'].lower() == kid and l['link']['publisher'].lower() == publisher), None)


def manifest_pin(config):
    manifest = json.loads((Path(config['workload'])/'compose-manifest.json').read_bytes())
    env = json.loads(manifest['docker_compose_file'])['services']['node']['environment']
    return json.loads(env['PAYMENTS_CONFIG']).get('enrollmentKeyId')


def check(config, dead_kid=None, need_gas=True):
    """Every precondition of a rotation, read-only. Logs what it found; raises on the first one that fails."""
    runner = Path(config['runner'])
    kid = kid_of(runner/'enrollment')
    if dead_kid and kid != dead_kid:
        raise RuntimeError('runner/enrollment holds %s, not the dead key %s' % (kid, dead_kid))
    for follower in config['followers']:
        if os.readlink(Path(follower)/'enrollment') != str(runner/'enrollment'):
            raise RuntimeError('%s/enrollment must link to %s' % (follower, runner/'enrollment'))
    for path in (runner/'DsmackRunner.app/Contents/MacOS/dsmack-runner', Path(config['dsmack']), Path(config['launcher']),
                 Path(config['probe'][0])):
        if not os.access(path, os.X_OK):
            raise RuntimeError('not executable: %s' % path)
    auth = json.loads(Path(config['authorization']).read_bytes())
    publisher = Account.from_key(Path(config['publisher_key']).read_text().strip()).address.lower()
    provisioner = Account.from_key(Path(config['provisioner_key']).read_text().strip()).address.lower()
    if provisioner != auth['authorization']['provisioner'].lower():
        raise RuntimeError('provisioner key %s is not the authorized %s' % (provisioner, auth['authorization']['provisioner']))
    state, link = broker_link(config, publisher, kid)
    if state['domain'] != auth['domain']:
        raise RuntimeError('authorization domain %s differs from the broker ownership domain %s' % (auth['domain'], state['domain']))
    # For an enrolled key, simulating its enroll checks the calldata and intermediate id against the chain. An
    # unenrolled key's leaf may have expired, so it is not simulated; the new key is simulated before it is sent.
    chain_key, (_, data) = key(config, kid), enroll_call(runner/'enrollment', config)
    simulated = 'not enrolled; not simulated'
    if chain_key['enrolled']:
        try:
            simulated = chain(config, '/call', to=config['registry'], data=data)['result']
        except RuntimeError as error:
            simulated = str(error)
        if 'already enrolled' not in simulated:
            raise RuntimeError('enroll simulation for enrolled %s did not revert with already enrolled: %s' % (kid, simulated))
        simulated = 'reverted: already enrolled'
    keys = Path(config['state'])/'keys.json'
    gas = Account.from_key(Path(config['gas_key']).read_text().strip())
    price = int(rpc(config, 'eth_gasPrice'), 16) * 2
    result = {'kid': kid, 'chain_key': chain_key, 'dead_keys': json.loads(keys.read_bytes()) if keys.exists() else {},
              'manifest_pin': manifest_pin(config), 'followers': config['followers'], 'publisher': publisher,
              'provisioner': provisioner, 'operator': auth['authorization']['operator'], 'broker_link': link,
              'enroll_simulation_current_key': simulated, 'gas_wallet': gas.address,
              'gas_balance_wei': int(chain(config, '/balance', address=gas.address)['wei']), 'enroll_cost_wei': price * config['gas_limit']}
    log('check', **result)
    if need_gas and result['gas_balance_wei'] < result['enroll_cost_wei']:
        raise RuntimeError('gas wallet %s holds %d wei; an enroll needs %d' % (gas.address, result['gas_balance_wei'], result['enroll_cost_wei']))
    return result


class Rotation:
    def __init__(self, config_path, dead_kid, resume):
        self.config, self.dead_kid, self.resume = json.loads(config_path.read_bytes()), dead_kid, resume
        self.watch = KeyWatch(config_path)
        self.runner = Path(self.config['runner'])
        self.work = Path(self.config['state'])/('rotation-' + dead_kid[2:])
        self.probes = Path(self.config['state'])/('probe-' + dead_kid[2:10] + '-' + str(time.time_ns()))
        self.progress = self.work/'progress.json'
        if resume and not self.work.exists():
            raise FileNotFoundError(self.work)
        if not resume and self.work.exists():
            raise FileExistsError(self.work)
        self.done = json.loads(self.progress.read_bytes()) if self.progress.exists() else {}

    def step(self, name, run):
        if name in self.done:
            log(name, status='already done', **self.done[name])
            return self.done[name]
        log(name, status='start')
        self.done[name] = run()
        write_json(self.progress, self.done)
        log(name, status='done', **self.done[name])
        return self.done[name]

    def runner_enroll(self, out, work):
        challenge = work/(out.name + '.challenge')
        challenge.write_bytes(secrets.token_bytes(32))
        subprocess.run([self.config['launcher'], '-n', '-W', '--stdout', str(work/(out.name + '.stdout')), '--stderr',
                        str(work/(out.name + '.stderr')), str(self.runner/'DsmackRunner.app'), '--args', 'enroll', str(out),
                        str(challenge)], check=True, timeout=900)
        # open(1) exits 0 whatever the app did; the three files are the only evidence the enroll worked.
        if not all((out/f).is_file() for f in ('keyId.txt', 'clientData.bin', 'attestation.cbor')):
            raise RuntimeError('runner enroll wrote no enrollment into %s: %s' % (out, (work/(out.name + '.stderr')).read_text(errors='replace')))

    def probe(self, enrollment, name):
        """One short hvf-v3 run with ENROLLMENT's key on the pool's workload: True if the runner signed its launch
        assertion, False if it failed to sign."""
        runner, run = self.probes/name/'runner', self.probes/name/'run-probe'
        runner.mkdir(parents=True)
        run.mkdir()
        for part in ('base', 'DsmackRunner.app', 'runtime'):
            os.symlink(self.runner/part, runner/part)
        os.symlink(enrollment, runner/'enrollment')
        workload = Path(self.config['workload'])
        os.link(workload/'workload.img', run/'workload.img')
        shutil.copyfile(workload/'compose-manifest.json', run/'compose-manifest.json')
        vm = json.loads((workload/'compose-manifest.json').read_bytes())['base_vm']
        with (self.probes/name/'probe.log').open('w') as out:
            subprocess.run(self.config['probe'] + [str(runner), str(run), '120', 'mini-%d-%d' % (vm['memory_mb'], vm['vcpus'])],
                           stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, check=True, timeout=900)
        for path in [run/'workload.img', *(run/'out').glob('*.img*')]:
            path.unlink()
        signed = (run/'out/launch-assertion.cbor').is_file()
        log('probe', key=name, kid=kid_of(enrollment), signed=signed, run=str(run))
        if not signed and not key_failure(run, None):
            raise RuntimeError('probe %s neither signed nor failed to sign; inspect %s' % (name, run))
        return signed

    def confirm_dead(self):
        """Probe the suspect key against a throwaway key. Anything short of proof of death clears the suspicion."""
        try:
            if kid_of(self.runner/'enrollment') != self.dead_kid:
                raise RuntimeError('runner/enrollment no longer holds %s' % self.dead_kid)
            self.probes.mkdir(parents=True)
            if self.probe(self.runner/'enrollment', 'current'):
                self.watch.clear(self.dead_kid)
                log('key_healthy', kid=self.dead_kid, note='the current key signs; suspicion cleared, nothing rotated')
                return False
            self.runner_enroll(self.probes/'throwaway', self.probes)
            if not self.probe(self.probes/'throwaway', 'throwaway'):
                raise RuntimeError('a fresh throwaway key fails to sign too, so this is not a dead key')
        except BaseException:
            self.watch.clear(self.dead_kid)
            log('suspicion_cleared', kid=self.dead_kid)
            raise
        self.watch.set(self.dead_kid, dead_at=int(time.time()), probes=str(self.probes))
        log('key_dead', kid=self.dead_kid, probes=str(self.probes))
        return True

    def enroll(self):
        new = self.runner/('enrollment.new-' + str(time.time_ns()))
        self.runner_enroll(new, self.work)
        kid, data = enroll_call(new, self.config)
        if kid == self.dead_kid:
            raise RuntimeError('runner enroll returned the dead key')
        # A fresh key that cannot attest is not a dead key; the simulation also catches an unadmitted CDHash.
        simulated = chain(self.config, '/call', to=self.config['registry'], data=data)['result']
        if simulated != '0x' + kid[2:]:
            raise RuntimeError('enroll simulation returned %s, not %s' % (simulated, kid))
        return {'dir': str(new), 'kid': kid}

    def sign(self, kid, data):
        gas = Account.from_key(Path(self.config['gas_key']).read_text().strip())
        tx = {'to': self.config['registry'], 'data': data, 'value': 0, 'gas': self.config['gas_limit'],
              'gasPrice': int(rpc(self.config, 'eth_gasPrice'), 16) * 2, 'chainId': self.config['chain_id'],
              'nonce': int(rpc(self.config, 'eth_getTransactionCount', gas.address, 'pending'), 16)}
        signed = gas.sign_transaction(tx)
        return {'from': gas.address, 'tx': '0x' + signed.hash.hex().removeprefix('0x'),
                'raw': '0x' + signed.raw_transaction.hex().removeprefix('0x')}

    def confirm(self, kid, tx):
        deadline = time.time() + self.config.get('confirm_seconds', 600)
        while (receipt := rpc(self.config, 'eth_getTransactionReceipt', tx)) is None:
            if time.time() > deadline:
                raise RuntimeError('no receipt for %s' % tx)
            time.sleep(5)
        if receipt['status'] != '0x1':
            return {'tx': tx, 'reverted': True}
        while not (state := key(self.config, kid))['enrolled']:
            if time.time() > deadline:
                raise RuntimeError('keys(%s) not enrolled at the verified head after %s' % (kid, tx))
            time.sleep(10)
        return {'tx': tx, 'block': int(receipt['blockNumber'], 16), 'expires': state['expires']}

    def link(self, kid):
        c = self.config
        out = self.work/'link.json'
        subprocess.run([c['dsmack'], 'link', '--broker', c['broker'], '--authorization', c['authorization'],
                        '--provisioner-key', c['provisioner_key'], '--publisher-key', c['publisher_key'], '--kid', kid,
                        '--out', str(out)], check=True, timeout=120)
        operator = json.loads(Path(c['authorization']).read_bytes())['authorization']['operator'].lower()
        publisher = Account.from_key(Path(c['publisher_key']).read_text().strip()).address.lower()
        _, link = broker_link(c, publisher, kid)
        if not link or link['operator'].lower() != operator:
            raise RuntimeError('broker shows no MacLink %s -> %s after dsmack link: %s' % (kid, operator, link))
        return link

    def switch(self, new, kid):
        current = self.runner/'enrollment'
        if kid_of(current) != self.dead_kid:
            raise RuntimeError('runner/enrollment no longer holds the dead key %s' % self.dead_kid)
        backup = self.runner/('enrollment.dead-' + self.dead_kid[2:10] + '-' + str(int(time.time())))
        os.rename(current, backup)
        os.rename(new, current)
        for follower in self.config['followers']:
            if kid_of(Path(follower)/'enrollment') != kid:
                raise RuntimeError('%s/enrollment does not hold %s after the switch' % (follower, kid))
        return {'backup': str(backup), 'kid': kid}

    def run(self):
        if not self.resume:
            if not self.confirm_dead():
                return
            self.work.mkdir()
        check(self.config, None if 'switch' in self.done else self.dead_kid, 'send' not in self.done)
        new = self.step('enroll', self.enroll)
        signed = self.step('sign', lambda: self.sign(new['kid'], enroll_call(Path(new['dir']), self.config)[1]))
        self.step('send', lambda: {'tx': rpc(self.config, 'eth_sendRawTransaction', signed['raw'])})
        if self.step('confirm', lambda: self.confirm(new['kid'], signed['tx'])).get('reverted'):
            raise RuntimeError('enroll transaction %s reverted, so this rotation is over: %s is still dead and runner/enrollment is '
                               'unchanged (%s is unused). Recover: find the cause (an Apple leaf older than three days, a CDHash '
                               'CDRegistry does not admit, gas), fix it, `mv %s %s.reverted` and run `key_rotation.py rotate` '
                               'again, which enrolls another fresh key.' % (signed['tx'], self.dead_kid, new['dir'], self.work, self.work))
        self.step('link', lambda: self.link(new['kid']))
        self.step('switch', lambda: self.switch(Path(new['dir']), new['kid']))
        pin = manifest_pin(self.config)
        if pin and pin.lower() != new['kid']:
            raise RuntimeError('switched to %s; the line runners use it from their next launch. The pool is NOT restarted: its '
                               'workload %s pins enrollmentKeyId %s, so the broker would refuse its guests. The running '
                               'generation keeps heartbeating and refuses launches. Once the workload no longer pins the key '
                               '(or is repacked with %s and its class registered), run `key_rotation.py resume` to restart it.'
                               % (new['kid'], self.config['workload'], pin, new['kid']))
        self.step('restart', lambda: {'command': subprocess.run(self.config['restart'], check=True, timeout=120).args})
        log('rotated', kid=new['kid'])


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('check', 'rotate', 'resume', 'dead-clear'):
        s = sub.add_parser(name)
        s.add_argument('--config', type=Path, required=True)
        if name in ('rotate', 'resume'):
            s.add_argument('--dead-kid', required=True)
        if name == 'dead-clear':
            s.add_argument('--kid', required=True)
    sub.add_parser('new-gas-wallet').add_argument('path', type=Path)
    a = p.parse_args()
    if a.command == 'new-gas-wallet':
        account = Account.create()
        with os.fdopen(os.open(a.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
            out.write(account.key.hex().removeprefix('0x') + '\n')
        a.path.with_suffix('.address').write_text(account.address + '\n')
        print(account.address)
        return
    if a.command == 'dead-clear':
        watch = KeyWatch(a.config)
        log('dead-clear', kid=a.kid.lower(), was=watch.keys().get(a.kid.lower()))
        watch.clear(a.kid.lower())
        return
    if a.command == 'check':
        check(json.loads(a.config.read_bytes()))
        for step in ('probe', 'enroll', 'sign', 'send', 'confirm', 'link', 'switch', 'restart'):
            log('would ' + step)
        return
    Rotation(a.config, a.dead_kid.lower(), a.command == 'resume').run()


if __name__ == '__main__':
    main()
