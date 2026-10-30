"""Replacement readiness must not discard the serving warm node."""
import hashlib
import json
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

    def instance(self, root):
        instance = object.__new__(pool.Pool)
        instance.args = SimpleNamespace(repo=Path('/repo'), cycles=0, replace_after=450, readiness_timeout=90,
                                        debugfs=Path('/debugfs'))
        instance.active = []; instance.stopping = False; instance.failure = None
        instance.consecutive_failures = 0; instance.last_error = None; instance.retry_pending = False
        instance.measurement = 'compose'; instance.image = 'image'
        instance.event = Mock(); instance.launch = Mock()
        return instance

    def failed_node(self, root):
        root.mkdir(exist_ok=True); (root/'evidence').mkdir(exist_ok=True)
        return {'process': Mock(poll=Mock(return_value=0), returncode=0), 'path': root, 'node': None}

    def test_failed_guest_is_replaced_without_stopping_healthy_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            healthy = {'process': Mock(poll=Mock(return_value=None)), 'node': {'relay_peer': 'healthy'},
                       'started': pool.time.monotonic(), 'admit_seconds': 570}
            failed = self.failed_node(root/'failed')
            instance.active = [healthy, failed]
            failure = {'stage': 'broker lease renewal 3/3', 'status': 503, 'body': 'promotion', 'error': 'actual error'}
            with patch.object(pool, 'guest_result', return_value={'error': failure}), \
                    patch.object(pool, 'preserve_and_retire', return_value={'retired_allocated_bytes': 123}) as retire:
                instance.tick()
            retire.assert_called_once_with(failed['path'], Path('/repo'))
            self.assertEqual(instance.active, [healthy]); self.assertFalse(instance.stopping)
            instance.launch.assert_called_once()
            self.assertEqual(instance.consecutive_failures, 1)
            self.assertEqual(json.loads((failed['path']/'evidence/guest-error.json').read_text()), failure)

    def test_closed_result_with_failed_service_is_replaced_even_after_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            node = self.failed_node(root/'failed'); node['node'] = {'relay_peer': 'was-ready'}
            instance.active = [node]
            result = {'outputs': {'status': 'failed', 'exit_code': 1},
                      'error': {'stage': 'broker lease renewal 3/3', 'error': 'lease failed', 'status': 403, 'body': 'refused'}}
            with patch.object(pool, 'guest_result', return_value=result), patch.object(pool, 'guest_closed', return_value=True), \
                    patch.object(pool, 'preserve_and_retire', return_value={}):
                instance.tick()
            self.assertEqual(instance.consecutive_failures, 1)
            self.assertFalse(instance.stopping); instance.launch.assert_called_once()

    def test_three_consecutive_failures_stop_with_last_actual_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            for number in range(1, 4):
                node = self.failed_node(root/str(number)); instance.active = [node]
                failure = {'stage': 'broker registration', 'status': 403, 'body': 'refused-'+str(number), 'error': 'HTTP 403'}
                with patch.object(pool, 'guest_result', return_value={'error': failure}), \
                        patch.object(pool, 'preserve_and_retire', return_value={}):
                    instance.tick()
            self.assertTrue(instance.stopping); self.assertEqual(instance.consecutive_failures, 3)
            self.assertIn('refused-3', instance.failure)
            self.assertEqual(instance.launch.call_count, 2)
            self.assertEqual(instance.event.call_args.kwargs['last_error'], failure)

    def test_broker_verified_ready_resets_consecutive_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance = self.instance(Path(tmp)); instance.consecutive_failures = 2
            now = pool.time.monotonic()
            instance.active = [{'process': Mock(poll=Mock(return_value=None)), 'node': None, 'path': Path(tmp),
                                'previous': set(), 'readiness_deadline': now+90, 'started': now, 'admit_seconds': 570}]
            ready = {'kind': 'compute', 'relay_peer': 'new', 'manifest_sha256': 'compose', 'os_image_hash': 'image',
                     'attestation': {'status': 'verified'}}
            with patch.object(instance, 'nodes', return_value=[ready]):
                instance.tick()
            self.assertEqual(instance.consecutive_failures, 0)
            self.assertEqual(instance.active[0]['node'], ready)

    def test_readiness_timeout_waits_for_only_that_owned_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance = self.instance(Path(tmp))
            node = {'process': Mock(poll=Mock(return_value=None)), 'node': None, 'path': Path(tmp),
                    'previous': set(), 'readiness_deadline': 0}
            instance.active = [node]
            with patch.object(instance, 'nodes', return_value=[]): instance.tick()
            self.assertTrue(node['readiness_failed']); self.assertFalse(instance.stopping)
            instance.launch.assert_not_called()

    def test_guest_diagnostics_retain_receipt_bound_http_body_status_and_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp); (run/'out').mkdir()
            message = 'POST /relay-broker/nodes: HTTP 503 body="promotion\\nretry" read=<nil>'
            gateway = (json.dumps({'event': 'registration_renewal_error', 'stage': 'broker lease renewal 3/3', 'error': message})+'\n').encode()
            stderr = ('2026/10/30 12:00:00 '+message+'\n').encode()
            declaration = lambda data: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            outputs = {'status': 'failed', 'exit_code': 1, 'stderr': declaration(stderr),
                       'artifacts': [dict(declaration(gateway), name='gateway-log')], 'missing': []}
            files = {'receipt.json': json.dumps({'outputs': outputs}).encode(), 'outputs/streams/stderr': stderr,
                     'outputs/artifacts/gateway-log': gateway}
            def read(argv, **kwargs):
                path = argv[2].removeprefix('cat /compute-node-v1/')
                return SimpleNamespace(stdout=files[path], stderr=b'debugfs 1.47.0 (5-Feb-2023)\n')
            with patch.object(pool, 'stopped_helper'), patch.object(pool.subprocess, 'run', side_effect=read):
                result = pool.guest_result(run, Path('/debugfs'))
            self.assertEqual(result['error']['status'], 503)
            self.assertEqual(result['error']['body'], 'promotion\nretry')
            self.assertEqual(result['error']['stage'], 'broker lease renewal 3/3')
            self.assertEqual((run/'out/guest-stderr.log').read_bytes(), stderr)
            self.assertEqual((run/'out/gateway-log.jsonl').read_bytes(), gateway)

    def test_guest_gateway_error_is_available_when_old_manifest_did_not_capture_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp); (run/'out').mkdir()
            message = 'POST /relay-broker/nodes: HTTP 403 body="bad attestation" read=<nil>'
            gateway = (json.dumps({'event': 'node_gateway_error', 'error': message})+'\n').encode()
            receipt = {'outputs': {'status': 'failed', 'stderr': None, 'artifacts': [
                {'name': 'gateway-log', 'bytes': len(gateway), 'sha256': hashlib.sha256(gateway).hexdigest()}]}}
            responses = [json.dumps(receipt).encode(), gateway]
            with patch.object(pool, 'stopped_helper'), patch.object(pool.subprocess, 'run', side_effect=[
                    SimpleNamespace(stdout=raw, stderr=b'debugfs 1.47.0\n') for raw in responses]):
                result = pool.guest_result(run, Path('/debugfs'))
            self.assertEqual(result['error']['stage'], 'POST /relay-broker/nodes')
            self.assertEqual(result['error']['body'], 'bad attestation')
            self.assertEqual(result['error']['status'], 403)
            self.assertFalse((run/'out/guest-stderr.log').exists())

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
