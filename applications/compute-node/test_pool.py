"""Replacement readiness must not discard the serving warm node."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pool


class PoolTests(unittest.TestCase):
    def test_replacement_starts_before_old_node_admission_closes(self):
        old = {'node': {'relay_peer': 'old'}, 'started': 0, 'admit_seconds': 570}
        self.assertFalse(pool.should_replace([old], 449, 450))
        self.assertTrue(pool.should_replace([old], 450, 450))
        new = {'node': {'relay_peer': 'new'}, 'started': 450, 'admit_seconds': 570}
        self.assertFalse(pool.should_replace([old, new], 570, 450))
        self.assertTrue(pool.should_replace([new], 900, 450))

    def test_only_new_verified_matching_registration_is_ready(self):
        base = {'kind': 'compute', 'relay_peer': 'old', 'manifest_sha256': 'compose', 'os_image_hash': 'image',
                'attestation': {'status': 'verified'}}
        good = dict(base, relay_peer='new')
        self.assertIsNone(pool.ready_node([base, dict(good, attestation={}), dict(good, os_image_hash='other')],
                                         {'old'}, 'compose', 'image'))
        self.assertEqual(pool.ready_node([base, good], {'old'}, 'compose', 'image'), good)

    def test_preflight_rejects_other_lanes_runner_and_allows_owned_overlap(self):
        disk = SimpleNamespace(free=20 << 30)
        process = SimpleNamespace(returncode=0, stdout='123 /runner/MacOS/dsmack-runner\n')
        with patch.object(pool.shutil, 'disk_usage', return_value=disk), patch.object(pool.subprocess, 'run', return_value=process), \
                patch.object(pool.subprocess, 'check_output', return_value='/runner/MacOS/dsmack-runner hvf-v3 /other/session.json'):
            with self.assertRaisesRegex(RuntimeError, 'another lane'):
                pool.preflight(Path('/state'), [{'path': Path('/owned')}])
        with patch.object(pool.shutil, 'disk_usage', return_value=disk), patch.object(pool.subprocess, 'run', return_value=process), \
                patch.object(pool.subprocess, 'check_output', return_value='/runner/MacOS/dsmack-runner hvf-v3 /owned/session.json'):
            result = pool.preflight(Path('/state'), [{'path': Path('/owned')}])
            self.assertEqual(result['owned_runner_sessions'], ['/owned/session.json'])
