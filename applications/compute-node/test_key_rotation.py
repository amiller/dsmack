"""A dead App Attest key is detected in the pool and replaced: fake runner, fake chain, fake broker."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from eth_account import Account

import key_rotation as kr

HERE = Path(__file__).resolve().parent
FIXTURE = HERE/'testdata/enrollment-46blYUmZ'
NEW_KID = '0xe3a6e5614999084a848e3eed83b3f2a91193c1ce6100d9eb806a557922a93046'
DEAD_FIXTURE = HERE/'testdata/enrollment-E9xjVkO1'
DEAD_KID = '0x13dc635643b52a9450735acb5fd55463e96e2a98051c18badc9c0295fce67de3'
REGISTRY = '0x04f57D219B1CEaE7f000C2a3360Ce49CffF3162e'
DOMAIN = {'name': 'DsmackMacOwnership', 'version': '1', 'chainId': 84532, 'verifyingContract': '0x835A61a88Cc8D750b5a971219aa8f9813B2067e6'}
OPERATOR = '0x1fbe7a7b3f7a37a967f3d927abd6f04db2766c5b'


class EnrollCallTests(unittest.TestCase):
    def test_calldata_is_byte_for_byte_the_one_submitted_for_46blYUmZ(self):
        config = {'intermediate_id': '0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90',
                  'intermediate_sha256': '39ef7264e1340f9adda4199d3a028fdece2ecd7bf7372420fe808ad6da538426'}
        kid, data = kr.enroll_call(FIXTURE, config)
        self.assertEqual(kid, NEW_KID)
        self.assertEqual(data, (HERE/'testdata/enroll-46blYUmZ.calldata').read_text().strip())
        self.assertEqual(kr.KEYS.hex(), 'dde5b7a1')
        with self.assertRaisesRegex(ValueError, 'Apple intermediate'):
            kr.enroll_call(FIXTURE, dict(config, intermediate_sha256='00'*32))


class KeyWatchTests(unittest.TestCase):
    def test_two_consecutive_signing_failures_make_a_key_suspect_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp)/'rotation.json'
            config.write_text(json.dumps({'state': str(Path(tmp)/'state')}))
            watch = kr.KeyWatch(config)
            self.assertFalse(watch.observe('0xa', True))
            self.assertFalse(watch.observe('0xa', False))
            self.assertFalse(watch.observe('0xa', True))
            self.assertTrue(watch.observe('0xa', True))
            self.assertFalse(watch.observe('0xa', True))
            self.assertNotIn('dead_at', watch.keys()['0xa'])
            watch.require_live('0xb')
            # A later generation reads the same state.
            with self.assertRaisesRegex(kr.KeyUnusable, 'suspect'):
                kr.KeyWatch(config).require_live('0xa')

    def test_signing_failures_are_read_from_guest_error_or_runner_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            guest = {'stage': 'POST /v1/Attest', 'error': 'App Attest: Error Domain=com.apple.devicecheck.error Code=0 "(null)"'}
            self.assertTrue(kr.key_failure(run, guest))
            self.assertFalse(kr.key_failure(run, {'stage': 'broker_registration', 'status': 403}))
            (run/'stderr.txt').write_text('mar: hvf-v3 failed: Error Domain=com.apple.devicecheck.error Code=0 "(null)"\n')
            self.assertTrue(kr.key_failure(run, None))


class Fake(http.server.BaseHTTPRequestHandler):
    """layover-chain, a JSON-RPC node and the broker's ownership routes, in one server."""
    def log_message(self, *_):
        pass

    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        s, url = self.server.chain, urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        verified = {'verified_by': 'helios-opstack'}
        if url.path == '/chain/balance':
            return self.reply({'wei': str(s['wei']), **verified})
        if url.path == '/chain/call' and q['data'].startswith('0x' + kr.KEYS.hex()):
            enrolled = q['data'][10:] in s['enrolled']
            return self.reply({'result': '0x' + '00'*64 + (1899590400 if enrolled else 0).to_bytes(32, 'big').hex() + '00'*32
                               + int(enrolled).to_bytes(32, 'big').hex(), **verified})
        if url.path == '/chain/call':
            kid = next(k for k in (NEW_KID[2:], DEAD_KID[2:]) if k in q['data'])
            return self.reply({'result': '0x' + kid, **verified} if kid not in s['enrolled']
                              else {'error': 'helios eth_call: execution reverted: revert: already enrolled'})
        if url.path == '/broker/fleet/ownership':
            return self.reply({'domain': DOMAIN, 'links': s['links'], 'revocations': [], 'nonces': {}})
        self.send_error(404)

    def do_POST(self):
        s, body = self.server.chain, json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path == '/broker/fleet/link':
            s['links'].append({'link': body['link']})
            return self.reply(body)
        method = body['method']
        if method == 'eth_sendRawTransaction':
            s['sent'].append(body['params'][0])
            s['enrolled'].add(NEW_KID[2:])
            return self.reply({'result': '0x' + '11'*32})
        result = {'eth_gasPrice': '0x3b9aca00', 'eth_getTransactionCount': '0x0',
                  'eth_getTransactionReceipt': {'status': s['status'], 'blockNumber': '0x10'} if s['sent'] else None}[method]
        self.reply({'result': result})


FAKE_OPEN = '''#!%s
import shutil, sys
a = sys.argv[sys.argv.index('--args')+1:]
assert a[0] == 'enroll' and len(open(a[2], 'rb').read()) == 32
shutil.copytree(%r, a[1])
''' % (sys.executable, str(FIXTURE))

FAKE_PROBE = '''#!%s
import json, pathlib, sys
runner, run = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
assert (run/'workload.img').is_file() and sys.argv[3:] == ['120', 'mini-4096-1']
signs = json.loads((pathlib.Path(%r)/'signs.json').read_text())
if (runner/'enrollment/keyId.txt').read_text().strip() in signs:
    (run/'out').mkdir(); (run/'out/launch-assertion.cbor').write_bytes(b'assertion'); (run/'out/scratch.img').write_bytes(b'x')
else:
    (run/'stderr.txt').write_text('mar: hvf-v3 failed: Error Domain=com.apple.devicecheck.error Code=0 "(null)"')
'''

FAKE_DSMACK = '''#!%s
import json, sys, urllib.request
a = dict(zip(sys.argv[2::2], sys.argv[3::2]))
link = {'kid': a['--kid'], 'publisher': %r, 'operator': %r, 'nonce': '3'}
urllib.request.urlopen(urllib.request.Request(a['--broker'] + '/fleet/link', json.dumps({'link': link}).encode(), {'Content-Type': 'application/json'}))
open(a['--out'], 'w').write(json.dumps(link))
'''


class RotationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = self.root = Path(tmp.name)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake)
        server.chain = self.chain = {'enrolled': {DEAD_KID[2:]}, 'wei': 10**18, 'links': [], 'sent': [], 'status': '0x1'}
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = 'http://127.0.0.1:%d' % server.server_port
        runner, follower = root/'runner', root/'lines/runner'
        (runner/'DsmackRunner.app/Contents/MacOS').mkdir(parents=True)
        shutil.copytree(DEAD_FIXTURE, runner/'enrollment')
        follower.mkdir(parents=True)
        os.symlink(str(runner/'enrollment'), follower/'enrollment')
        keys = {}
        for name in ('gas', 'provisioner', 'publisher'):
            keys[name] = Account.create()
            (root/(name+'.key')).write_text(keys[name].key.hex())
        (root/'authorization.json').write_text(json.dumps({'domain': DOMAIN, 'signature': '0x', 'authorization': {
            'operator': OPERATOR, 'provisioner': keys['provisioner'].address.lower(), 'nonce': '1'}}))
        scripts = {'DsmackRunner.app/Contents/MacOS/dsmack-runner': '#!/bin/sh\n', 'open': FAKE_OPEN,
                   'dsmack': FAKE_DSMACK % (sys.executable, keys['publisher'].address.lower(), OPERATOR),
                   'probe': FAKE_PROBE % (sys.executable, str(root))}
        for name, text in scripts.items():
            path = (runner if name.startswith('Dsmack') else root)/name
            path.write_text(text)
            path.chmod(0o755)
        (root/'workload').mkdir()
        (root/'workload/workload.img').write_bytes(b'workload')
        self.signs([(FIXTURE/'keyId.txt').read_text().strip()])
        self.config = {
            'runner': str(runner), 'followers': [str(follower)], 'workload': str(root/'workload'), 'state': str(root/'state'),
            'registry': REGISTRY, 'intermediate_id': '0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90',
            'intermediate_sha256': '39ef7264e1340f9adda4199d3a028fdece2ecd7bf7372420fe808ad6da538426',
            'rpc': base + '/rpc', 'chain_read': base + '/chain', 'chain_id': 84532, 'gas_key': str(root/'gas.key'), 'gas_limit': 16000000,
            'dsmack': str(root/'dsmack'), 'launcher': str(root/'open'), 'authorization': str(root/'authorization.json'),
            'provisioner_key': str(root/'provisioner.key'), 'publisher_key': str(root/'publisher.key'),
            'broker': base + '/broker', 'restart': ['touch', str(root/'restarted')], 'confirm_seconds': 5,
            'probe': [str(root/'probe')]}
        self.config_path = root/'key-rotation.json'
        self.config_path.write_text(json.dumps(self.config))
        self.pin(None)

    def signs(self, key_ids):
        (self.root/'signs.json').write_text(json.dumps(key_ids))

    def keys(self):
        return kr.KeyWatch(self.config_path).keys()

    def pin(self, kid):
        payments = json.dumps({'node': '0xclass'} | ({'enrollmentKeyId': kid} if kid else {}))
        compose = json.dumps({'services': {'node': {'environment': {'PAYMENTS_CONFIG': payments}}}})
        (self.root/'workload/compose-manifest.json').write_text(json.dumps({'docker_compose_file': compose,
                                                                            'base_vm': {'memory_mb': 4096, 'vcpus': 1}}))

    def rotate(self, resume=False):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                kr.Rotation(self.config_path, DEAD_KID, resume).run()
            finally:
                self.log = [json.loads(line) for line in out.getvalue().splitlines()]

    def test_rotation_enrolls_links_switches_and_restarts(self):
        self.rotate()
        runner = self.root/'runner'
        self.assertEqual(kr.kid_of(runner/'enrollment'), NEW_KID)
        self.assertEqual(kr.kid_of(self.root/'lines/runner/enrollment'), NEW_KID)
        backups = list(runner.glob('enrollment.dead-13dc6356-*'))
        self.assertEqual([kr.kid_of(b) for b in backups], [DEAD_KID])
        self.assertEqual(len(self.chain['sent']), 1)
        tx = Account.recover_transaction(self.chain['sent'][0])
        self.assertEqual(tx, Account.from_key((self.root/'gas.key').read_text()).address)
        self.assertEqual([l['link']['kid'] for l in self.chain['links']], [NEW_KID])
        self.assertTrue((self.root/'restarted').exists())
        self.assertEqual(self.log[-1]['step'], 'rotated')
        self.assertEqual([(l['key'], l['signed']) for l in self.log if l['step'] == 'probe'], [('current', False), ('throwaway', True)])
        self.assertIn('dead_at', self.keys()[DEAD_KID])
        self.assertFalse(list((self.root/'state').glob('probe-*/*/run-probe/workload.img')))
        self.assertFalse(list((self.root/'state').glob('probe-*/*/run-probe/out/*.img')))
        self.assertTrue((self.root/'workload/workload.img').exists())
        with self.assertRaises(FileExistsError):
            kr.Rotation(self.config_path, DEAD_KID, False)

    def test_a_key_that_signs_again_is_cleared_not_rotated(self):
        kr.KeyWatch(self.config_path).set(DEAD_KID, failures=2, suspect_at=1)
        self.signs([(DEAD_FIXTURE/'keyId.txt').read_text().strip()])
        self.rotate()
        self.assertEqual(self.log[-1]['step'], 'key_healthy')
        self.assertNotIn(DEAD_KID, self.keys())
        self.assertFalse(self.chain['sent'])
        self.assertFalse((self.root/'state'/('rotation-' + DEAD_KID[2:])).exists())
        self.assertEqual(kr.kid_of(self.root/'runner/enrollment'), DEAD_KID)

    def test_a_throwaway_key_that_fails_too_clears_the_suspicion(self):
        kr.KeyWatch(self.config_path).set(DEAD_KID, failures=2, suspect_at=1)
        self.signs([])
        with self.assertRaisesRegex(RuntimeError, 'throwaway key fails to sign too'):
            self.rotate()
        self.assertNotIn(DEAD_KID, self.keys())
        self.assertFalse(self.chain['sent'])
        kr.KeyWatch(self.config_path).require_live(DEAD_KID)

    def test_reverted_enroll_ends_the_rotation_and_the_documented_recovery_works(self):
        self.chain['status'] = '0x0'
        work = self.root/'state'/('rotation-' + DEAD_KID[2:])
        with self.assertRaisesRegex(RuntimeError, 'reverted, so this rotation is over.*mv %s %s.reverted' % (work, work)):
            self.rotate()
        with self.assertRaisesRegex(RuntimeError, 'reverted, so this rotation is over'):
            self.rotate(resume=True)
        self.assertEqual(len(self.chain['sent']), 1)
        self.assertEqual(kr.kid_of(self.root/'runner/enrollment'), DEAD_KID)
        self.assertFalse(self.chain['links'])
        self.chain['status'] = '0x1'
        self.chain['enrolled'].discard(NEW_KID[2:])
        work.rename(str(work) + '.reverted')
        self.rotate()
        self.assertEqual(len(self.chain['sent']), 2)
        self.assertEqual(kr.kid_of(self.root/'runner/enrollment'), NEW_KID)

    def test_enroll_that_writes_nothing_fails_before_any_transaction(self):
        # open(1) exits 0 and leaves the app's stderr in the --stderr file.
        (self.root/'open').write_text('#!/bin/sh\nwhile [ "$1" != --stderr ]; do shift; done\necho "App Attest unsupported" > "$2"\n')
        with self.assertRaisesRegex(RuntimeError, 'runner enroll wrote no enrollment.*App Attest unsupported'):
            self.rotate()
        self.assertFalse(self.chain['sent'])
        self.assertNotIn(DEAD_KID, self.keys())

    def test_a_pinned_manifest_switches_the_lines_but_does_not_restart_the_pool(self):
        self.pin(DEAD_KID)
        with self.assertRaisesRegex(RuntimeError, 'pool is NOT restarted.*pins enrollmentKeyId %s' % DEAD_KID):
            self.rotate()
        self.assertEqual(kr.kid_of(self.root/'lines/runner/enrollment'), NEW_KID)
        self.assertFalse((self.root/'restarted').exists())
        self.pin(None)
        self.rotate(resume=True)
        self.assertTrue((self.root/'restarted').exists())
        self.assertEqual(len(self.chain['sent']), 1)

    def test_dead_clear_revives_a_key(self):
        kr.KeyWatch(self.config_path).set(DEAD_KID, dead_at=1)
        with self.assertRaises(kr.KeyUnusable):
            kr.KeyWatch(self.config_path).require_live(DEAD_KID)
        with mock.patch.object(sys, 'argv', ['key_rotation.py', 'dead-clear', '--config', str(self.config_path), '--kid', DEAD_KID]), \
                contextlib.redirect_stdout(io.StringIO()):
            kr.main()
        kr.KeyWatch(self.config_path).require_live(DEAD_KID)

    def test_dry_run_checks_without_writing(self):
        with contextlib.redirect_stdout(io.StringIO()):
            result = kr.check(self.config)
        self.assertEqual(result['kid'], DEAD_KID)
        self.assertIn('already enrolled', result['enroll_simulation_current_key'])
        self.assertFalse((self.root/'state').exists())
        os.unlink(self.root/'lines/runner/enrollment')
        os.symlink(str(self.root/'runner/enrollment.old'), self.root/'lines/runner/enrollment')
        with self.assertRaisesRegex(RuntimeError, 'must link to'):
            kr.check(self.config)

    def test_unfunded_gas_wallet_is_refused_after_the_other_checks_are_logged(self):
        self.chain['wei'] = 0
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaisesRegex(RuntimeError, 'holds 0 wei; an enroll needs 32000000000000000'):
            kr.check(self.config)
        self.assertEqual(json.loads(out.getvalue())['kid'], DEAD_KID)
        with self.assertRaisesRegex(RuntimeError, 'holds 0 wei'):
            self.rotate()
        self.assertFalse(list((self.root/'runner').glob('enrollment.new-*')))
        self.chain['wei'] = 10**18
        self.rotate(resume=True)
        self.assertEqual(kr.kid_of(self.root/'runner/enrollment'), NEW_KID)


if __name__ == '__main__':
    unittest.main()
