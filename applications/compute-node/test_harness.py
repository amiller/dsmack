"""Concrete scan-boundary and on-disk tampering failures for the live harness."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import success_harness as harness


class HostEvidence(unittest.TestCase):
    def test_marker_spanning_read_boundary_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markers = harness.new_markers()
            for name, raw in markers.items():
                (root/name).write_bytes(b'x' * 73 + raw + b'_' + raw.hex().encode() + b'_' + base64.b64encode(raw))
            scan = harness.scan([root], markers, chunk_size=80)
            self.assertFalse(scan['passed'])
            for name in markers:
                self.assertEqual({h['encoding'] for h in scan['hits'] if h['marker'] == name}, {'raw', 'hex', 'base64'})
            self.assertTrue(harness.scan([root], markers, control=True, chunk_size=80)['passed'])

    @unittest.skipUnless(Path('/usr/sbin/debugfs').exists() and Path('/usr/sbin/mkfs.ext4').exists(), 'ext4 tools required')
    def test_tamper_changes_one_byte_in_actual_result_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = root/'result.img'
            with disk.open('wb') as stream:
                stream.truncate(8 << 20)
            subprocess.run(['/usr/sbin/mkfs.ext4', '-q', '-F', str(disk)], check=True, capture_output=True)
            result = root/'result.json'
            result.write_bytes(harness.canonical({'outputs': {'patch': {'ct': 'abcdef0123456789' * 8}}}))
            subprocess.run(['/usr/sbin/debugfs', '-w', '-R', 'write ' + str(result) + ' /sealed', str(disk)],
                           check=True, capture_output=True)
            original, tampered, change = harness.flip_output(disk, '/sealed')
            self.assertEqual(original, result.read_bytes())
            self.assertEqual(sum(a != b for a, b in zip(original, tampered)), 1)
            self.assertNotEqual(json.loads(original)['outputs']['patch']['ct'], json.loads(tampered)['outputs']['patch']['ct'])
            self.assertEqual(change['bytes_changed'], 1)


if __name__ == '__main__':
    unittest.main()
