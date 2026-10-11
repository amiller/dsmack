"""Development staging authority tool: key custody and control-file signing."""
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coupon_staging_authority',
                                              ROOT / 'tools/coupon_staging_authority.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

sys.path.insert(0, str(ROOT))
from experiments.coupon_redemption.staging_approval import (APPROVAL_DOMAIN, approval,
                                                            configuration, payload_hash)
from experiments.coupon_redemption.test_live_fixture import approval_payload, config_payload


class StagingAuthorityTests(unittest.TestCase):
    def run_tool(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            tool.main(list(arguments))
        return json.loads(output.getvalue())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.addCleanup(self.temporary.cleanup)
        self.directory = self.root / 'authority'

    def test_generate_creates_protected_authority_and_refuses_overwrite(self):
        created = self.run_tool('generate', '--dir', str(self.directory))
        self.assertEqual(sorted(name for name in os.listdir(self.directory)),
                         ['README.txt', 'staging-authority.pub', 'staging-authority.seed'])
        info = os.stat(self.directory / 'staging-authority.seed')
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        # The published half names the same key and never the seed material.
        published = self.run_tool('public-key', '--dir', str(self.directory))
        self.assertEqual(published, created)
        self.assertNotIn('seed', json.dumps(published))
        with self.assertRaises(SystemExit):
            self.run_tool('generate', '--dir', str(self.directory))

    def test_signed_control_files_verify_under_the_real_validators(self):
        authority = self.run_tool('generate', '--dir', str(self.directory))
        public = bytes.fromhex(authority['public_key_hex'])
        operator = self.root / 'operator'
        operator.mkdir(mode=0o700)
        approved_payload = approval_payload()
        config = config_payload(operator)
        config['approval_sha256'] = payload_hash(APPROVAL_DOMAIN, approved_payload)
        for name, payload in (('approval.payload.json', approved_payload),
                              ('config.payload.json', config)):
            file = self.root / name
            file.write_text(json.dumps(payload))
            file.chmod(0o600)
        signed = self.run_tool('sign-approval', '--dir', str(self.directory),
            '--payload', str(self.root / 'approval.payload.json'),
            '--out', str(operator / 'approval.json'))
        self.assertEqual(signed['approval_sha256'],
                         payload_hash(APPROVAL_DOMAIN, approved_payload))
        self.run_tool('sign-config', '--dir', str(self.directory),
            '--payload', str(self.root / 'config.payload.json'),
            '--approval', str(self.root / 'approval.payload.json'),
            '--out', str(operator / 'config.json'))
        # The exact bytes the worker would read verify against this authority.
        envelope = (operator / 'approval.json').read_bytes()
        self.assertEqual(approval(envelope, public), approved_payload)
        self.assertEqual(configuration((operator / 'config.json').read_bytes(), public,
                                       approved_payload), config)
        # Outputs are created once only; a re-sign never overwrites silently.
        with self.assertRaises(SystemExit):
            self.run_tool('sign-approval', '--dir', str(self.directory),
                '--payload', str(self.root / 'approval.payload.json'),
                '--out', str(operator / 'approval.json'))

    def test_policy_violations_and_binding_failures_refuse_to_sign(self):
        self.run_tool('generate', '--dir', str(self.directory))
        operator = self.root / 'operator'
        operator.mkdir(mode=0o700)
        # A production-profile request is not a staging approval.
        private_profile = dict(approval_payload(), profile='private-issuance-qualified')
        file = self.root / 'bad.payload.json'
        file.write_text(json.dumps(private_profile))
        file.chmod(0o600)
        with self.assertRaises(SystemExit):
            self.run_tool('sign-approval', '--dir', str(self.directory),
                '--payload', str(self.root / 'bad.payload.json'),
                '--out', str(operator / 'approval.json'))
        self.assertFalse((operator / 'approval.json').exists())
        # A config bound to a different approval hash never signs.
        approved_payload = approval_payload()
        config = config_payload(operator)
        config['approval_sha256'] = 'ff' * 32
        for name, payload in (('approval.payload.json', approved_payload),
                              ('config.payload.json', config)):
            file = self.root / name
            file.write_text(json.dumps(payload))
            file.chmod(0o600)
        self.run_tool('sign-approval', '--dir', str(self.directory),
            '--payload', str(self.root / 'approval.payload.json'),
            '--out', str(operator / 'approval.json'))
        with self.assertRaises(SystemExit):
            self.run_tool('sign-config', '--dir', str(self.directory),
                '--payload', str(self.root / 'config.payload.json'),
                '--approval', str(self.root / 'approval.payload.json'),
                '--out', str(operator / 'config.json'))
        self.assertFalse((operator / 'config.json').exists())

    def write_payload(self, name, payload):
        file = self.root / name
        file.write_text(json.dumps(payload))
        file.chmod(0o600)
        return file

    def test_malformed_state_dir_or_issuer_peer_id_refuse_to_sign(self):
        # Review F2: the tool previously wrote a config with state_dir:123 (or
        # a list issuer_peer_id) without refusal; it must refuse via the real
        # configuration() validation before any file is created.
        self.run_tool('generate', '--dir', str(self.directory))
        operator = self.root / 'operator'
        operator.mkdir(mode=0o700)
        approved_payload = approval_payload()
        approval_file = self.write_payload('approval.payload.json', approved_payload)
        for field, value in (('state_dir', 123), ('state_dir', 'relative/state'),
                             ('issuer_peer_id', ['IssuerPeer00000001']),
                             ('issuer_peer_id', 'Short')):
            config = config_payload(operator)
            config['approval_sha256'] = payload_hash(APPROVAL_DOMAIN, approved_payload)
            config[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(SystemExit):
                    self.run_tool('sign-config', '--dir', str(self.directory),
                        '--payload', str(self.write_payload('config.payload.json', config)),
                        '--approval', str(approval_file),
                        '--out', str(operator / 'config.json'))
                self.assertFalse((operator / 'config.json').exists())

    def test_development_authority_directory_stays_ignored(self):
        """The shipped tool must never point operators at a committed path."""
        self.assertIn('local-data/', (ROOT / '.gitignore').read_text())
        self.assertNotIn(b'staging-authority.seed', subprocess.run(
            ['git', 'ls-files'], cwd=ROOT, capture_output=True).stdout)
        created = self.run_tool('generate', '--dir', str(self.directory))
        # The committed approval root stays null; the dev key is recorded only
        # in the ignored authority directory, never in the repository.
        self.assertEqual(json.loads((ROOT / 'packaging/coupon/approval-root.json').read_text()),
                         {'public_key_hex': None})
        self.assertNotIn(created['public_key_hex'],
                         (ROOT / 'packaging/coupon/approval-root.json').read_text())


if __name__ == '__main__':
    unittest.main()
