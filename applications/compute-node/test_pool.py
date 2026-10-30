"""Replacement readiness must not discard the serving warm node."""
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest.mock import Mock, patch

import pool


class PoolTests(unittest.TestCase):
    def test_operator_capacity_accepts_four_guests_and_names_oversized_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'operator.json'
            config = {'max_guests': 4, 'guest': {'mem_mib': 4096, 'vcpus': 1},
                      'reserve': {'mem_gb': 16, 'cores': 4}}
            host = {'mem_bytes': 64 << 30, 'cores': 14}
            path.write_text(json.dumps(config))
            self.assertEqual(pool.operator_config(path, host), config)
            config['max_guests'] = 20
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, '81920 MiB.*physical 65536 MiB.*reserve 16384 MiB.*49152 MiB available.*20.*14 cores.*4.*10 available'):
                pool.operator_config(path, host)
            config['max_guests'] = 4; config['guest']['vcpus'] = 3
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, '12.*14 cores.*4.*10 available'):
                pool.operator_config(path, host)

    def test_operator_size_must_match_attested_resource_profile(self):
        config = {'guest': {'mem_mib': 8192, 'vcpus': 2}}
        manifest = {'base_vm': {'memory_mb': 8192, 'vcpus': 2},
                    'resource_profiles': {'mini-8192-2': {'mem_mib': 8192, 'vcpus': 2}}}
        self.assertEqual(pool.measured_size(manifest, config), 'mini-8192-2')
        manifest['base_vm']['memory_mb'] = 4096
        with self.assertRaisesRegex(ValueError, 'differs from measured resource profile'):
            pool.measured_size(manifest, config)

    def test_restart_preserves_full_broker_429_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = {'max_guests': 4, 'guest': {'mem_mib': 4096, 'vcpus': 1},
                      'reserve': {'mem_gb': 16, 'cores': 4}}
            (root/'operator.json').write_text(json.dumps(config))
            manifest = {'base_vm': {'os_image_hash': 'image', 'memory_mb': 4096, 'vcpus': 1},
                        'resource_profiles': {'mini-4096-1': config['guest']},
                        'docker_compose_file': json.dumps({'services': {'node': {'environment': {
                            'PAYMENTS_CONFIG': json.dumps({'operator': 'payout', 'node': 'class'})}}}})}
            (root/'compose-manifest.json').write_text(json.dumps(manifest))
            args = SimpleNamespace(operator=root/'operator.json', workload=root, publisher_key=None)
            error = {'at': 1793379629, 'slot_id': 2, 'stage': 'broker_registration', 'status': 429,
                     'error': 'POST /nodes: HTTP 429', 'body': 'egress request rate exceeded'}
            with patch.object(pool, 'hardware', return_value={'mem_bytes': 64 << 30, 'cores': 14}):
                first = pool.Pool(args)
                first.remember_error(error)
                restarted = pool.Pool(args)
            self.assertEqual(restarted.errors, [error])
            self.assertEqual(json.loads((root/'operator-errors.json').read_bytes()), [error])

    def test_failed_slot_does_not_stop_other_slot_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            instance.slots[0]['stopped'] = True
            instance.slots.append(dict(instance.slots[0], slot_id=1, stopped=False))
            instance.tick()
            instance.launch.assert_called_once_with(instance.slots[1])
            self.assertFalse(instance.stopping)

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
        instance.errors_file = root/'operator-errors.json'
        instance.slots = [{'slot_id': 0, 'consecutive_failures': 0, 'last_error': None, 'retry_pending': False, 'stopped': False, 'jobs_served': 0}]; instance.last_broker_error = None; instance.errors = []
        instance.measurement = 'compose'; instance.image = 'image'; instance.last_status_poll = pool.time.monotonic()
        instance.event = Mock(); instance.launch = Mock()
        return instance

    def failed_node(self, root):
        root.mkdir(exist_ok=True); (root/'evidence').mkdir(exist_ok=True)
        return {'slot_id': 0, 'process': Mock(poll=Mock(return_value=0), returncode=0), 'path': root, 'node': None}

    def test_failed_guest_is_replaced_without_stopping_healthy_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            healthy = {'slot_id': 0, 'process': Mock(poll=Mock(return_value=None)), 'node': {'relay_peer': 'healthy'},
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
            self.assertEqual(instance.slots[0]['consecutive_failures'], 1)
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
            self.assertEqual(instance.slots[0]['consecutive_failures'], 1)
            self.assertFalse(instance.stopping); instance.launch.assert_called_once()

    def test_three_consecutive_failures_stop_only_that_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            for number in range(1, 4):
                node = self.failed_node(root/str(number)); instance.active = [node]
                failure = {'stage': 'broker registration', 'status': 403, 'body': 'refused-'+str(number), 'error': 'HTTP 403'}
                with patch.object(pool, 'guest_result', return_value={'error': failure}), \
                        patch.object(pool, 'preserve_and_retire', return_value={}):
                    instance.tick()
            self.assertFalse(instance.stopping); self.assertTrue(instance.slots[0]['stopped'])
            self.assertEqual(instance.slots[0]['consecutive_failures'], 3)
            self.assertIn('refused-3', instance.slots[0]['last_error']['body'])
            self.assertEqual(instance.launch.call_count, 2)
            self.assertEqual(instance.event.call_args.kwargs['last_error'], failure)

    def test_readiness_does_not_erase_failed_guest_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance = self.instance(Path(tmp)); instance.slots[0]['consecutive_failures'] = 2
            now = pool.time.monotonic()
            instance.active = [{'slot_id': 0, 'process': Mock(poll=Mock(return_value=None)), 'node': None, 'path': Path(tmp),
                                'previous': set(), 'readiness_deadline': now+90, 'started': now, 'admit_seconds': 570}]
            ready = {'kind': 'compute', 'relay_peer': 'new', 'manifest_sha256': 'compose', 'os_image_hash': 'image',
                     'attestation': {'status': 'verified'}}
            with patch.object(instance, 'nodes', return_value=[ready]):
                instance.tick()
            self.assertEqual(instance.slots[0]['consecutive_failures'], 2)
            self.assertEqual(instance.active[0]['node'], ready)

    def test_readiness_timeout_waits_for_only_that_owned_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance = self.instance(Path(tmp))
            node = {'slot_id': 0, 'process': Mock(poll=Mock(return_value=None)), 'node': None, 'path': Path(tmp),
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
            agent_receipts = (json.dumps({'sessionId': '01'*16, 'node_peer': 'guest-peer',
                                         'guestSeconds': 3, 'final': True, 'sig': '02'*64})+'\n').encode()
            tool_log = b'agent tool server ready\n'
            declaration = lambda data: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            outputs = {'status': 'failed', 'exit_code': 1, 'stderr': declaration(stderr),
                       'artifacts': [dict(declaration(gateway), name='gateway-log'),
                                     dict(declaration(agent_receipts), name='agent-receipts'),
                                     dict(declaration(tool_log), name='tool-server-log')], 'missing': []}
            files = {'receipt.json': json.dumps({'outputs': outputs}).encode(), 'outputs/streams/stderr': stderr,
                     'outputs/artifacts/gateway-log': gateway, 'outputs/artifacts/agent-receipts': agent_receipts,
                     'outputs/artifacts/tool-server-log': tool_log}
            def read(argv, **kwargs):
                path = argv[2].removeprefix('cat /compute-node-v1/')
                return SimpleNamespace(stdout=files[path], stderr=b'debugfs 1.47.0 (5-Feb-2023)\n')
            with patch.object(pool, 'stopped_helper'), patch.object(pool.subprocess, 'run', side_effect=read):
                result = pool.guest_result(run, Path('/debugfs'))
            self.assertEqual(result['error']['status'], 503)
            self.assertEqual(result['error']['body'], 'promotion\nretry')
            self.assertEqual(result['error']['stage'], 'broker lease renewal 3/3')
            self.assertTrue(result['error']['terminal'])
            self.assertEqual((run/'out/guest-stderr.log').read_bytes(), stderr)
            self.assertEqual((run/'out/gateway-log.jsonl').read_bytes(), gateway)
            self.assertEqual((run/'out/agent-receipts.jsonl').read_bytes(), agent_receipts)
            self.assertEqual((run/'out/tool-server.log').read_bytes(), tool_log)

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
            self.assertEqual(result['error']['stage'], 'broker_registration')
            self.assertEqual(result['error']['body'], 'bad attestation')
            self.assertEqual(result['error']['status'], 403)
            self.assertFalse((run/'out/guest-stderr.log').exists())

    def test_broker_promotion_outage_keeps_booting_vm_and_reports_failure(self):
        import time
        from urllib.error import HTTPError
        instance = self.instance(Path('/unused'))
        instance.args = SimpleNamespace(broker='https://broker', readiness_timeout=90, cycles=0, replace_after=450)
        node = {'slot_id': 0, 'process': Mock(poll=Mock(return_value=None)), 'node': None,
                'path': Path('/owned'), 'previous': set(), 'readiness_deadline': 0, 'started': time.monotonic()}
        instance.active = [node]; instance.stopping = False; instance.failure = None
        instance.measurement = 'compose'; instance.image = 'image'; instance.last_status_poll = pool.time.monotonic()
        instance.event = Mock(); instance.launch = Mock()
        with patch.object(pool, 'urlopen', side_effect=HTTPError('https://broker',500,'unavailable',None,None)):
            instance.tick()
        self.assertEqual(instance.active, [node])
        self.assertGreater(node['readiness_deadline'], time.monotonic())
        event = instance.event.call_args
        self.assertEqual(event.args, ('broker_unavailable',))
        self.assertEqual(event.kwargs['stage'], 'broker_readiness')
        self.assertEqual(event.kwargs['status'], 500)
        self.assertEqual(event.kwargs['body'], '')
        instance.launch.assert_not_called()

    def test_broker_404_does_not_stop_healthy_guest_and_is_counted_after_failed_guest_finishes(self):
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root); instance.args.broker = 'https://broker'
            now = pool.time.monotonic()
            healthy = {'slot_id': 0, 'process': Mock(poll=Mock(return_value=None)), 'node': {'relay_peer': 'healthy'},
                       'started': now, 'admit_seconds': 570}
            booting = self.failed_node(root/'booting'); booting.update(process=Mock(poll=Mock(return_value=None)),
                previous=set(), started=now, admit_seconds=570, readiness_deadline=0)
            instance.active = [healthy, booting]
            error = HTTPError('https://broker/nodes', 404, 'missing', None, io.BytesIO(b'actual missing route'))
            with patch.object(pool, 'urlopen', side_effect=error): instance.tick()
            self.assertEqual(instance.active, [healthy, booting]); self.assertFalse(instance.stopping)
            self.assertEqual(instance.slots[0]['consecutive_failures'], 0)
            self.assertEqual(booting['readiness_error']['status'], 404)
            self.assertEqual(booting['readiness_error']['body'], 'actual missing route')
            booting['process'] = Mock(poll=Mock(return_value=0), returncode=0)
            with patch.object(pool, 'guest_result', return_value={'outputs': {'status': 'failed'}}), \
                    patch.object(pool, 'preserve_and_retire', return_value={}): instance.tick()
            self.assertEqual(instance.slots[0]['consecutive_failures'], 1)
            self.assertEqual(instance.slots[0]['last_error']['status'], 404)
            self.assertEqual(instance.slots[0]['last_error']['stage'], 'broker_readiness')
            self.assertEqual(instance.active, [healthy]); instance.launch.assert_called_once()

    def test_legacy_socket_timeout_is_reported_without_stopping_the_pool(self):
        # Python 3.9 on the Mac raises socket.timeout as OSError, not TimeoutError.
        with tempfile.TemporaryDirectory() as tmp:
            instance = self.instance(Path(tmp)); instance.args.broker = 'https://broker'
            with patch.object(pool, 'urlopen', side_effect=OSError('The read operation timed out')):
                self.assertIsNone(instance.nodes())
            self.assertFalse(instance.stopping)
            self.assertEqual(instance.last_broker_error['error_type'], 'OSError')

    def test_broker_error_response_body_is_bounded_and_malformed_200_is_visible(self):
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as tmp:
            instance = self.instance(Path(tmp)); instance.args.broker = 'https://broker'
            error = HTTPError('https://broker/nodes', 503, 'promotion', None, io.BytesIO(b'x'*5000))
            with patch.object(pool, 'urlopen', side_effect=error): self.assertIsNone(instance.nodes())
            self.assertEqual(len(instance.last_broker_error['body']), 4096)
            response = Mock(status=200); response.read.return_value = b'<html>wrong deployment</html>'
            response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
            with patch.object(pool, 'urlopen', return_value=response): self.assertIsNone(instance.nodes())
            self.assertEqual(instance.last_broker_error['status'], 200)
            self.assertEqual(instance.last_broker_error['body'], '<html>wrong deployment</html>')

    def test_ready_guest_at_bounded_lifetime_is_retired_without_counting_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            node = self.failed_node(root/'normal'); node['node'] = {'relay_peer': 'was-ready'}
            instance.active = [node]
            result = {'outputs': {'status': 'cancelled', 'exit_code': None, 'cancel': {'reason': 'timeout'}}, 'error': None}
            with patch.object(pool, 'guest_result', return_value=result), patch.object(pool, 'guest_closed', return_value=True), \
                    patch.object(pool, 'preserve_and_retire', return_value={}): instance.tick()
            self.assertEqual(instance.slots[0]['consecutive_failures'], 0)
            self.assertFalse(instance.stopping)
            self.assertEqual(instance.event.call_args.args, ('retired',))

    def test_old_transient_renewal_error_does_not_fail_normal_bounded_retirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            node = self.failed_node(root/'normal'); node['node'] = {'relay_peer': 'was-ready'}
            instance.active = [node]
            result = {'outputs': {'status': 'cancelled', 'cancel': {'reason': 'timeout'}},
                      'error': {'stage': 'broker lease renewal 1/3', 'error': 'transient HTTP 503', 'terminal': False}}
            with patch.object(pool, 'guest_result', return_value=result), patch.object(pool, 'guest_closed', return_value=True), \
                    patch.object(pool, 'preserve_and_retire', return_value={}): instance.tick()
            self.assertEqual(instance.slots[0]['consecutive_failures'], 0)
            self.assertEqual(instance.event.call_args.args, ('retired',))

    def test_timeout_with_actual_guest_error_is_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); instance = self.instance(root)
            node = self.failed_node(root/'failed'); node['node'] = {'relay_peer': 'was-ready'}
            instance.active = [node]
            result = {'outputs': {'status': 'cancelled', 'cancel': {'reason': 'timeout'}},
                      'error': {'stage': 'broker_registration', 'status': 403, 'body': 'refused', 'error': 'actual refusal'}}
            with patch.object(pool, 'guest_result', return_value=result), patch.object(pool, 'guest_closed', return_value=True), \
                    patch.object(pool, 'preserve_and_retire', return_value={}): instance.tick()
            self.assertEqual(instance.slots[0]['consecutive_failures'], 1)
            self.assertEqual(instance.slots[0]['last_error']['body'], 'refused')

    def test_uncertain_live_helper_blocks_extraction_and_retirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'helper-stopped.json').write_text('{"pid":123}')
            with patch.object(pool.os, 'kill'), patch.object(pool.subprocess, 'run') as read:
                with self.assertRaisesRegex(RuntimeError, 'helper remains active'):
                    pool.guest_result(root, Path('/debugfs'))
                read.assert_not_called()
