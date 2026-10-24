import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from inspect_runner import inspect
SPEC = importlib.util.spec_from_file_location('cd_args', HERE.parents[1] / 'contracts/cd_args.py')
CD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CD)


def fixture():
    # Three pages, deliberately partial last page; alternate SHA-1 CD too.
    body = bytearray(32781)
    struct.pack_into('<8I', body, 0, 0xfeedfacf, 0x100000c, 0, 2, 1, 16, 0, 0)
    ent = struct.pack('>II', 0xfade7172, 11) + b'der'
    def directory(htype):
        hsize = 32 if htype == 2 else 20
        names = b'dev.example.runner\0TEAM123\0'
        table = 96 + len(names) + 7 * hsize
        size = table + 3 * hsize
        result = bytearray(size)
        struct.pack_into('>9I', result, 0, 0xfade0c02, size, 0x20500, 0x10000,
                         table, 96, 7, 3, len(body))
        struct.pack_into('4B', result, 36, hsize, htype, 0, 14)
        struct.pack_into('>I', result, 48, 96 + len(b'dev.example.runner\0'))
        result[96:96 + len(names)] = names
        algorithm = 'sha256' if htype == 2 else 'sha1'
        result[table - 7 * hsize:table - 6 * hsize] = hashlib.new(algorithm, ent).digest()
        for i in range(3):
            result[table + i*hsize:table + (i+1)*hsize] = hashlib.new(
                algorithm, body[i*16384:(i+1)*16384]).digest()
        return bytes(result)
    provisional = [(0, directory(2)), (0x1000, directory(1)), (7, ent)]
    size = 12 + 8 * len(provisional) + sum(len(blob) for _, blob in provisional)
    struct.pack_into('<4I', body, 32, 0x1d, 16, len(body), size)
    blobs = [(0, directory(2)), (0x1000, directory(1)), (7, ent)]
    index, contents, off = [], [], 12 + 8 * len(blobs)
    for slot, blob in blobs:
        index.append(struct.pack('>II', slot, off))
        contents.append(blob)
        off += len(blob)
    superblob = struct.pack('>III', 0xfade0cc0, size, len(blobs)) + b''.join(index + contents)
    return bytes(body) + superblob, hashlib.sha256(blobs[0][1]).hexdigest()


class InspectionTests(unittest.TestCase):
    def test_every_directory_and_partial_page(self):
        report, _ = CD.inspect_bytes(fixture()[0])
        self.assertEqual([3, 3], [d['code_pages_verified'] for d in report['code_directories']])
        self.assertEqual([7], report['code_directories'][0]['embedded_special_slots_verified'])
        self.assertFalse(report['apple_signature_verified'])

    def test_changed_nonzero_page(self):
        b = bytearray(fixture()[0]); b[20000] ^= 1
        with self.assertRaisesRegex(ValueError, 'page mismatch'):
            CD.inspect_bytes(b)

    def test_changed_partial_last_page(self):
        b = bytearray(fixture()[0]); b[32780] ^= 1
        with self.assertRaisesRegex(ValueError, 'page mismatch'):
            CD.inspect_bytes(b)

    def test_changed_embedded_entitlements(self):
        b = bytearray(fixture()[0]); b[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'special-slot mismatch'):
            CD.inspect_bytes(b)

    def test_wrong_identity_and_cdhash(self):
        b, digest = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runner'; path.write_bytes(b); path.chmod(0o600)
            self.assertTrue(inspect(path, digest, 'TEAM123', 'dev.example.runner')['expected_identity_matched'])
            for expected in [(digest, 'OTHER', 'dev.example.runner'),
                             (digest, 'TEAM123', 'wrong.bundle'), ('0'*64, 'TEAM123', 'dev.example.runner')]:
                with self.assertRaises(ValueError): inspect(path, *expected)

    def test_bounds_duplicate_slot_and_trailing_bytes(self):
        b, _ = fixture()
        for variant in (b[:8], b[:-1], b + b'x'):
            with self.assertRaises(ValueError): CD.inspect_bytes(variant)
        b = bytearray(b)
        struct.pack_into('>I', b, 32781 + 20, 0)
        with self.assertRaisesRegex(ValueError, 'duplicate signature slot'): CD.inspect_bytes(b)

    def test_unsupported_scatter(self):
        b = bytearray(fixture()[0])
        struct.pack_into('>I', b, 32781 + 36 + 44, 1)
        with self.assertRaisesRegex(ValueError, 'scatter'): CD.inspect_bytes(b)

if __name__ == '__main__': unittest.main()
