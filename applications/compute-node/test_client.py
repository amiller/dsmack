"""Network boundary checks: measured key binding and authenticated output decryption."""
import copy
import io
import json
from pathlib import Path
import struct
import time
import tempfile
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

import client

ROOT = Path(__file__).resolve().parents[2]


class ClientBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = json.loads((ROOT/'applications/relay-broker/fixtures/compute.json').read_bytes())
        cls.manifest = (ROOT/'applications/compute-node/testdata/compose-manifest.json').read_bytes()
        cls.enrollment = ROOT/'applications/agent-turns/testdata/v02-turn/enrollment'
        # H's captured assertion predates the measured model field. Replay its
        # cryptographic binding with the exact historical measurements.
        cls.policy = object.__new__(client.Policy)
        cls.policy.measurement = client.sha(cls.manifest)
        cls.policy.image = json.loads(cls.manifest)['base_vm']['os_image_hash']
        cls.policy.cdhash = cls.node['cdhash']
        cls.policy.rule = client.policy(bytes.fromhex(cls.node['cdhash']))
        cls.policy.kid = (cls.enrollment/'keyId.txt').read_text().strip()
        cls.policy.key = client.verify_key((cls.enrollment/'attestation.cbor').read_bytes(), cls.policy.kid,
                              (cls.enrollment/'clientData.bin').read_bytes(), cls.policy.rule,
                              client.root(), time.time())['public_key']

    def test_compose_must_measure_the_approved_model(self):
        manifest = json.loads(self.manifest)
        compose = json.loads(manifest['docker_compose_file'])
        compose['services']['node']['environment']['MODEL'] = client.MODEL
        manifest['docker_compose_file'] = client.canonical(compose).decode()
        client.Policy(client.canonical(manifest), self.enrollment, self.node['cdhash'])
        compose['services']['node']['environment']['MODEL'] = 'different-model'
        manifest['docker_compose_file'] = client.canonical(compose).decode()
        with self.assertRaisesRegex(ValueError, 'compose model'):
            client.Policy(client.canonical(manifest), self.enrollment, self.node['cdhash'])

    def test_generated_compose_can_be_admitted(self):
        # A reserved environment name rejects the workload before it can boot.
        import workload
        import sys
        sys.path.insert(0, str(ROOT/'base-vm/browser-sandbox-v1/source/runner-content/lib'))
        from dsmack_compose_contract.manifest import validate_manifest_bytes
        starter = ROOT/'applications/compute-node/testdata/compose-manifest.json'
        image = json.loads(json.loads(self.manifest)['docker_compose_file'])['services']['node']['image'].split('@')[1]
        raw = workload.manifest(starter, image, Path(workload.__file__),
                                self.node['relay_maddr'].split('/p2p-circuit/')[0],
                                'http://192.168.100.3:18271', '01' * 32, self.node['cdhash'], 420)
        validate_manifest_bytes(raw)

    def test_real_registration_requires_attested_peer_and_both_keys(self):
        a, signed = self.policy.verify_registration(self.node)
        self.assertGreater(signed['counter'], 0)
        self.assertEqual(len(a['run']), 32)
        for field, value in [('secret_key', client.public(ec.generate_private_key(ec.SECP256R1())).hex()),
                             ('receipt_key', '01' * 32)]:
            altered = dict(self.node, **{field: value})
            with self.assertRaisesRegex(ValueError, 'report_data'):
                self.policy.verify_registration(altered)
        altered = dict(self.node, relay_peer='12D3KooWPdcePFHp8pmoxdwpNC2ADNivvsCFYH8KPSfqutt7GWzA')
        altered['relay_maddr'] = self.node['relay_maddr'].rsplit('/', 1)[0] + '/' + altered['relay_peer']
        with self.assertRaisesRegex(ValueError, 'report_data'):
            self.policy.verify_registration(altered)

    def test_ciphertext_authentication_and_job_context(self):
        key = ec.generate_private_key(ec.SECP256R1())
        box = client.seal(client.public(key), 'job/patch', b'private patch')
        self.assertEqual(client.decrypt(key, 'job/patch', box), b'private patch')
        with self.assertRaises(InvalidTag):
            client.decrypt(key, 'other-job/patch', box)
        altered = copy.deepcopy(box)
        data = bytearray.fromhex(box['ct']); data[0] ^= 1; altered['ct'] = data.hex()
        with self.assertRaises(InvalidTag):
            client.decrypt(key, 'job/patch', altered)

    def test_expired_access_token_is_sealed_for_guest_refresh(self):
        oauth = {'accessToken': 'expired-access-token', 'refreshToken': 'refresh-token',
                 'expiresAt': 1, 'scopes': ['user:inference']}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'credential.json'
            path.write_bytes(client.canonical({'claudeAiOauth': oauth | {'localAccountMetadata': 'omit'}}))
            self.assertEqual(client.read_credential(path), {'claudeAiOauth': oauth})
            path.write_bytes(client.canonical({'claudeAiOauth': {'accessToken': 'expired-access-token', 'expiresAt': 1}}))
            with self.assertRaises(ValueError):
                client.read_credential(path)

    def test_control_frame_bound_checked_before_payload_read(self):
        stream = io.BytesIO(struct.pack('>I', 4097))
        with self.assertRaisesRegex(ValueError, 'frame bound'):
            client.recv(stream, 4096)


if __name__ == '__main__':
    unittest.main()
