import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coupon_package', ROOT / 'tools/coupon_package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageBoundary(unittest.TestCase):
    def test_wrapped_async_issuance_forks_then_spawns_transport_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / 'packaging/coupon/python-worker'
            wrapper.parent.mkdir(parents=True)
            wrapper.write_bytes((ROOT / 'packaging/coupon/python-worker').read_bytes())
            modules = root / 'experiments/coupon_redemption'
            modules.mkdir(parents=True)
            (root / 'experiments/__init__.py').write_text('')
            # Only the fixture entry point is substituted. AsyncCouponServiceV4,
            # Store, Near and NearHTTPS are imported from the actual runtime.
            (modules / '__init__.py').write_text(
                '__path__.append(' + repr(str(ROOT / 'experiments/coupon_redemption')) + ')\n')
            (modules / 'peer_worker.py').write_text('''
import hashlib
import http.client
import json
import socket
import sys
import tempfile
import time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def no_network(*args, **kwargs):
    raise AssertionError('network is forbidden in the nested issuance fixture')
socket.create_connection = socket.getaddrinfo = no_network

class FakeResponse:
    status = 200
    def getheader(self, name, default=None): return default
    def read(self, size): return b'{"id":"synthetic-key-id","key":"synthetic-only-secret"}'

class FakeConnection:
    def __init__(self, host, port, timeout, context):
        assert host == 'cloud-api.near.ai' and port == 443
    def request(self, method, target, body, headers):
        assert method == 'POST' and target == '/v1/workspaces/11111111-1111-1111-1111-111111111111/api-keys'
        assert headers['Authorization'] == 'Bearer synthetic-fixture-token'
        value = json.loads(body)
        assert value['name'].startswith('coupon-')
        assert value['spendLimit'] == {'amount': 100000000, 'currency': 'USD'}
    def getresponse(self): return FakeResponse()
    def close(self): pass
http.client.HTTPSConnection = FakeConnection

from .async_service_v4 import AsyncCouponServiceV4
from .near import Near
from .service import Principal
from .spike import Store
from .transport import NearHTTPS

if __name__ == '__main__':
    assert sys.argv[1:] == ['--fixture-async-spawn']
    with tempfile.TemporaryDirectory() as temporary:
        store = Store(Path(temporary) / 'state.sqlite')
        key = Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        issuer = {'peer_id': 'IssuerPeer00000001', 'policy': 'dstack-tdx-coupon-v1',
            'identity_policy_sha256': '11'*32, 'issuance_policy_sha256': '22'*32,
            'issuer_public_key_sha256': hashlib.sha256(raw).hexdigest()}
        provider = Near('11111111-1111-1111-1111-111111111111',
            '22222222-2222-2222-2222-222222222222',
            'synthetic-fixture-token', 'synthetic-fixture-reporting',
            NearHTTPS(deadline=5, socket_timeout=1))
        service = AsyncCouponServiceV4(store, provider, key,
            sponsor_subject='operator:sponsor', observer_subject='operator:observer',
            issuer_peer_id=issuer['peer_id'], provider_binding={'mode': 'near'},
            issuer_binding=issuer, issuance_authorizer=lambda *_: None,
            max_active_jobs=1, job_deadline_seconds=30)
        try:
            bundle = service.provision(Principal('operator:sponsor', frozenset({'sponsor'})),
                '100000000', '2099-01-01T00:00:00Z')
            public = X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            service._claim(bundle['coupon'], 'RecipientPeer00001', public, bundle['offer_hash'])
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                row = store.db.execute('SELECT state,key_id FROM coupons').fetchone()
                if row['state'] != 'issuing': break
                time.sleep(.02)
            assert row['state'] == 'delivered', row['state']
            assert row['key_id'] == 'synthetic-key-id'
            result = service._claim(bundle['coupon'], 'RecipientPeer00001', public, bundle['offer_hash'])
            assert result['key_id'] == 'synthetic-key-id' and result['envelope']
            for job in service.jobs.values():
                job.join(2)
                assert job.exitcode == 0
        finally:
            service.close_jobs()
            store.close()
    print('packaged async fork then transport spawn completed without network')
''')
            result = subprocess.run([sys.executable, str(wrapper), '-m',
                'experiments.coupon_redemption.peer_worker', '--fixture-async-spawn'],
                cwd=root, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(),
                             'packaged async fork then transport spawn completed without network')
            self.assertEqual(result.stderr, '')

    def test_wrapped_transport_spawn_reimports_module_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / 'packaging/coupon/python-worker'
            wrapper.parent.mkdir(parents=True)
            wrapper.write_bytes((ROOT / 'packaging/coupon/python-worker').read_bytes())
            modules = root / 'experiments/coupon_redemption'
            modules.mkdir(parents=True)
            (root / 'experiments/__init__.py').write_text('')
            (modules / '__init__.py').write_text('')
            (modules / 'transport.py').write_bytes((ROOT / 'experiments/coupon_redemption/transport.py').read_bytes())
            (modules / 'spike.py').write_text('class RedemptionError(Exception): pass\n')
            # Only this disposable fixture entry point is replaced. The actual
            # wrapper and NearHTTPS spawn/Pipe/deadline path run unchanged.
            (modules / 'peer_worker.py').write_text('''
import http.client
import json
import socket
import sys

def no_network(*args, **kwargs):
    raise AssertionError('network is forbidden in the packaged spawn fixture')
socket.create_connection = socket.getaddrinfo = no_network

class FakeResponse:
    status = 200
    def getheader(self, name, default=None): return default
    def read(self, size): return b'{"spawned_transport":true}'

class FakeConnection:
    def __init__(self, host, port, timeout, context):
        assert host == 'cloud-api.near.ai' and port == 443
    def request(self, method, target, body, headers):
        assert method == 'POST' and target == '/v1/workspaces/fixture/api-keys'
        assert headers['Authorization'] == 'Bearer synthetic-fixture-token'
        assert json.loads(body) == {'fixture': True}
    def getresponse(self): return FakeResponse()
    def close(self): pass

http.client.HTTPSConnection = FakeConnection
from .transport import NearHTTPS

if __name__ == '__main__':
    assert sys.argv[1:] == ['--fixture-spawn']
    result = NearHTTPS(deadline=5, socket_timeout=1)(
        'POST', 'https://cloud-api.near.ai/v1/workspaces/fixture/api-keys',
        'synthetic-fixture-token', {'fixture': True})
    assert result == {'spawned_transport': True}
    print('packaged spawned transport completed without network')
''')
            result = subprocess.run([sys.executable, str(wrapper), '-m',
                'experiments.coupon_redemption.peer_worker', '--fixture-spawn'],
                cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'packaged spawned transport completed without network')
            self.assertEqual(result.stderr, '')
            for arguments in [[], ['-c', 'pass'], ['-m', 'experiments.coupon_redemption.transport']]:
                refused = subprocess.run([sys.executable, str(wrapper), *arguments],
                    cwd=root, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('unsupported worker invocation', refused.stderr)

    def test_new_runtime_python_secret_is_not_exported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in package.DSMACK_FILES:
                file = root / name; file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'reviewed fixture bytes')
            (root / 'experiments/coupon_redemption/operator_secret.py').write_bytes(b'PRIVATE_PYTHON_CANARY')
            with patch.object(package, 'ROOT', root): selected = package.dsmack_files()
            self.assertNotIn('experiments/coupon_redemption/operator_secret.py', selected)
            self.assertNotIn(b'PRIVATE_PYTHON_CANARY', b''.join(selected.values()))

    def test_pinned_source_rejects_tamper_and_links_excludes_unlisted_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, metadata = root / 'source', root / 'metadata'
            source.mkdir(); metadata.mkdir()
            original = b'reviewed peer bytes'
            (source / 'peer.mjs').write_bytes(original)
            (source / 'operator.token').write_bytes(b'PRIVATE_CANARY')
            (metadata / 'paired-source.json').write_text(json.dumps({'revision': 'test', 'files': {'peer.mjs': hashlib.sha256(original).hexdigest()}}))
            with patch.object(package, 'PACKAGING', metadata):
                _, selected = package.paired_files(source)
                self.assertEqual(selected, {'peer.mjs': original})
                (source / 'peer.mjs').write_bytes(b'changed')
                with self.assertRaises(ValueError): package.paired_files(source)
                (source / 'peer.mjs').unlink()
                (source / 'original').write_bytes(original)
                (source / 'peer.mjs').symlink_to('original')
                with self.assertRaises(ValueError): package.paired_files(source)

    def test_archive_reproducible_and_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'a.tar.gz', root / 'b.tar.gz'
            package.archive(first, {'z': b'end', 'a': b'begin'})
            package.archive(second, {'a': b'begin', 'z': b'end'})
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                self.assertEqual(archive.getnames(), ['a', 'z'])
                self.assertTrue(all(member.uid == member.gid == member.mtime == 0 for member in archive.getmembers()))
            with self.assertRaises(ValueError): package.archive(first, {'a': b'replace'})

    def test_dependency_archive_rejects_traversal_links_and_duplicates(self):
        for name, kind, duplicate in [('../escape', tarfile.REGTYPE, False), ('peer', tarfile.SYMTYPE, False), ('peer', tarfile.REGTYPE, True)]:
            with self.subTest(name=name, kind=kind, duplicate=duplicate), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'bad.tar.gz'
                with tarfile.open(source, 'w:gz') as archive:
                    info = tarfile.TarInfo(name); info.type = kind; info.linkname = 'outside'
                    info.size = 0
                    archive.addfile(info, io.BytesIO())
                    if duplicate: archive.addfile(info, io.BytesIO())
                result = subprocess.run([sys.executable, str(ROOT / 'tools/coupon_pair_archive.py'), str(source), str(root / 'out')], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
