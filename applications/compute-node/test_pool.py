"""Replacement readiness must not discard the serving warm node."""
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
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

    def test_host_exit_without_guest_closure_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'out').mkdir(); console = root/'out/console-v3.log'
            console.write_text('DSMACK_SUPERVISOR_DONE runner_failures=1\nDSMACK_EXPORT_CLOSURE_REFUSED prior failure\n')
            self.assertFalse(pool.guest_closed(root))
            console.write_text('DSMACK_SUPERVISOR_DONE runner_failures=0\n')
            self.assertFalse(pool.guest_closed(root))
            console.write_text('DSMACK_SUPERVISOR_DONE runner_failures=0\nDSMACK_RESULT_CLOSED_V1 1234\n')
            self.assertTrue(pool.guest_closed(root))

    def test_zero_host_exit_with_guest_failure_stops_rotation_after_cleanup(self):
        instance = object.__new__(pool.Pool)
        instance.args = SimpleNamespace(repo=Path('/repo'), cycles=0)
        instance.active = [{'process': Mock(poll=Mock(return_value=0), returncode=0), 'path': Path('/owned'), 'node': None}]
        instance.stopping = False; instance.failure = None
        instance.event = Mock(); instance.launch = Mock()
        with patch.object(pool, 'preserve_and_retire', return_value={'retired_allocated_bytes': 123}) as retire:
            instance.tick()
        retire.assert_called_once_with(Path('/owned'), Path('/repo'))
        instance.launch.assert_not_called()
        self.assertTrue(instance.stopping)
        self.assertIsNotNone(instance.failure)
        self.assertEqual(instance.active, [])

    def test_broker_promotion_outage_keeps_booting_vm_and_reports_failure(self):
        import time
        from urllib.error import HTTPError
        instance = object.__new__(pool.Pool)
        instance.args = SimpleNamespace(broker='https://broker', readiness_timeout=90, cycles=0, replace_after=450)
        node = {'process': Mock(poll=Mock(return_value=None)), 'node': None,
                'path': Path('/owned'), 'previous': set(), 'readiness_deadline': 0, 'started': time.monotonic()}
        instance.active = [node]; instance.stopping = False; instance.failure = None
        instance.measurement = 'compose'; instance.image = 'image'
        instance.event = Mock(); instance.launch = Mock()
        with patch.object(pool, 'urlopen', side_effect=HTTPError('https://broker',500,'unavailable',None,None)):
            instance.tick()
        self.assertEqual(instance.active, [node])
        self.assertGreater(node['readiness_deadline'], time.monotonic())
        instance.event.assert_called_once_with('broker_unavailable', error='HTTPError', status=500)
        instance.launch.assert_not_called()

    def test_fatal_broker_readiness_response_drains_before_returning_error(self):
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as tmp:
            instance = object.__new__(pool.Pool)
            instance.args = SimpleNamespace(state=Path(tmp), cycles=0)
            instance.active = [object()]; instance.stopping = False; instance.failure = None
            instance.event = Mock()
            def tick():
                if not instance.stopping:
                    raise HTTPError('https://broker/nodes',404,'missing',None,None)
                instance.active.clear()
            instance.tick = tick
            with patch.object(pool.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'broker readiness HTTP 404'):
                    instance.run()
            self.assertTrue(instance.stopping)
            self.assertEqual(instance.active, [])
            instance.event.assert_called_once_with('draining_after_error',error='broker readiness HTTP 404')
