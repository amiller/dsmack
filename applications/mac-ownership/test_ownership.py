"""CLI boundary tests: keystore signing, idempotent commands, and secret output."""
import contextlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from eth_account import Account

import ownership


class CommandTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.operator = Account.create()
        self.provisioner = Account.create()
        self.publisher = Account.create()
        self.domain = {'name': 'DsmackMacOwnership', 'version': '1', 'chainId': 84532,
                       'verifyingContract': '0x' + '12' * 20}
        self.state = {'domain': self.domain, 'links': [], 'revocations': [],
                      'nonces': {'publishers': {}, 'kids': {}}}
        self.posts = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(owner.state).encode())

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.posts.append((self.path, data))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.broker = 'http://127.0.0.1:' + str(self.server.server_port)
        for name, account in [('publisher', self.publisher), ('provisioner', self.provisioner)]:
            (self.root / name).write_text('0x' + account.key.hex())
        encrypted = Account.encrypt(self.operator.key, 'test-password', kdf='pbkdf2', iterations=2)
        (self.root / 'operator').write_text(json.dumps(encrypted))
        (self.root / 'password').write_text('test-password\n')
        self.auth_path = self.root / 'authorization.json'
        self.kid = '0x' + '34' * 32

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = ownership.main([args[0], '--broker', self.broker, '--config', str(self.root / 'none'), *args[1:]])
        output = stdout.getvalue() + stderr.getvalue()
        for account in (self.operator, self.provisioner, self.publisher):
            self.assertNotIn(account.key.hex(), output)
        self.assertNotIn('test-password', output)
        return code, stdout.getvalue(), stderr.getvalue()

    def authorize(self, nonce=None):
        code, stdout, stderr = self.run_cli('authorize', '--operator-keystore', str(self.root / 'operator'),
            '--password-file', str(self.root / 'password'), '--provisioner', self.provisioner.address,
            '--out', str(self.auth_path), *(['--nonce', str(nonce)] if nonce is not None else []))
        self.assertEqual(code, 0, stderr)
        auth = json.loads(self.auth_path.read_text())
        self.assertEqual(ownership.recover(self.domain, 'ProvisioningAuthorization', auth['authorization'], auth['signature']), self.operator.address.lower())
        self.assertEqual(self.auth_path.stat().st_mode & 0o777, 0o600)
        return auth

    def test_foundry_authorization_and_repeated_link_use_same_signed_request(self):
        auth = self.authorize()
        args = ('link', '--authorization', str(self.auth_path), '--provisioner-key', str(self.root / 'provisioner'),
                '--publisher-key', str(self.root / 'publisher'), '--kid', self.kid)
        code, _, stderr = self.run_cli(*args)
        self.assertEqual(code, 0, stderr)
        first = self.posts[-1][1]
        self.assertEqual(first['link']['nonce'], '0')
        for field, account in [('publisherSignature', self.publisher), ('provisionerSignature', self.provisioner)]:
            self.assertEqual(ownership.recover(self.domain, 'MacLink', first['link'], first[field]), account.address.lower())
        self.state['links'] = [first]
        self.state['nonces'] = {'publishers': {self.publisher.address.lower(): '0'}, 'kids': {self.kid: '0'}}
        code, _, stderr = self.run_cli(*args)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(self.posts[-1][1], first)
        self.assertEqual(first['authorization']['signature'], auth['signature'])

    def test_revocation_survives_unlink_and_prevents_reauthorization(self):
        auth = self.authorize(nonce=10)
        self.state['links'] = [{'authorization': {'authorization': auth['authorization'], 'signature': auth['signature']}}]
        code, _, stderr = self.run_cli('revoke-provisioner', '--operator-keystore', str(self.root / 'operator'),
            '--password-file', str(self.root / 'password'), '--provisioner', self.provisioner.address)
        self.assertEqual(code, 0, stderr)
        route, body = self.posts[-1]
        self.assertEqual(route, '/fleet/revoke-provisioner')
        self.assertEqual(body['revocation']['nonce'], '11')
        self.assertEqual(ownership.recover(self.domain, 'ProvisionerRevocation', body['revocation'], body['signature']), self.operator.address.lower())
        self.state['links'] = []
        self.state['revocations'] = [body]
        code, _, stderr = self.run_cli('revoke-provisioner', '--operator-keystore', str(self.root / 'operator'),
            '--password-file', str(self.root / 'password'), '--provisioner', self.provisioner.address)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(self.posts[-1][1], body)
        code, stdout, stderr = self.run_cli('authorize', '--operator-keystore', str(self.root / 'operator'),
            '--password-file', str(self.root / 'password'), '--provisioner', self.provisioner.address,
            '--nonce', '100', '--out', str(self.root / 'revoked-authorization.json'))
        self.assertEqual(code, 1)
        self.assertEqual(stdout, '')
        self.assertIn('provisioner revoked; authorize a new provisioner key', stderr)
        self.assertFalse((self.root / 'revoked-authorization.json').exists())

    def test_bad_keystore_password_exits_without_prompt_or_secret(self):
        (self.root / 'password').write_text('wrong-password')
        code, stdout, stderr = self.run_cli('authorize', '--operator-keystore', str(self.root / 'operator'),
            '--password-file', str(self.root / 'password'), '--provisioner', self.provisioner.address,
            '--out', str(self.auth_path))
        self.assertEqual(code, 1)
        self.assertEqual(stdout, '')
        self.assertIn('cannot decrypt operator keystore', stderr)
        self.assertFalse(self.auth_path.exists())

    def test_tampered_operator_authorization_is_not_posted(self):
        auth = self.authorize()
        auth['authorization']['operator'] = self.publisher.address.lower()
        self.auth_path.write_text(json.dumps(auth))
        code, _, stderr = self.run_cli('link', '--authorization', str(self.auth_path),
            '--provisioner-key', str(self.root / 'provisioner'), '--publisher-key', str(self.root / 'publisher'), '--kid', self.kid)
        self.assertEqual(code, 1)
        self.assertIn('invalid operator authorization', stderr)
        self.assertEqual(self.posts, [])


if __name__ == '__main__':
    unittest.main()
