"""A discovery publication outage must not stop a serving Mac pool."""
import contextlib
import importlib.util
import io
import json
import os
import signal
import sys
import tempfile
import http.server
import threading
import time
from pathlib import Path
import subprocess
import unittest
from unittest import mock
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('mac_pool', Path(__file__).with_name('mac-pool.py'))
mac_pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mac_pool)


class PublicationTests(unittest.TestCase):
    def test_periodic_network_failure_and_timeout_allow_next_refresh(self):
        publish = Mock(side_effect=[subprocess.CalledProcessError(1, ['publish']),
                                   subprocess.TimeoutExpired(['publish'], 480), None])
        hint = {'url': 'wss://relay.example/', 'expiresAt': 123}
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            self.assertFalse(mac_pool.republish(publish, [hint], False))
            self.assertFalse(mac_pool.republish(publish, [hint], True))
            self.assertTrue(mac_pool.republish(publish, [hint], True))
        self.assertEqual(publish.call_count, 3)
        events = [json.loads(line) for line in log.getvalue().splitlines()]
        self.assertEqual([event['error'] for event in events], ['CalledProcessError', 'TimeoutExpired'])
        self.assertTrue(all(event['retrySeconds'] == 60 for event in events))

    def test_periodic_publication_does_not_mask_configuration_errors(self):
        with self.assertRaises(ValueError):
            mac_pool.republish(Mock(side_effect=ValueError('invalid publisher key')), {}, False)


class RestartBackoffTests(unittest.TestCase):
    def test_crashed_launchers_share_increasing_waits_before_transports(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = Path(tmp)/'launcher-backoff.json'
            clock = [1000]
            waits = []
            def sleep(seconds):
                waits.append(seconds); clock[0] += seconds
            with mock.patch.object(mac_pool.time, 'time', side_effect=lambda: clock[0]), \
                    mock.patch.object(mac_pool.time, 'sleep', side_effect=sleep):
                self.assertTrue(mac_pool.RestartBackoff(path).begin(lambda:False))
                for delay in (60, 120, 240, 480, 960, 1800, 1800):
                    waits.clear()
                    # Each new launcher gets a fresh generation but the same service root.
                    self.assertTrue(mac_pool.RestartBackoff(path).begin(lambda:False))
                    self.assertEqual(sum(waits), delay)

    def test_only_a_sustained_healthy_run_resets_failures_and_wait_can_be_stopped(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = Path(tmp)/'launcher-backoff.json'
            path.write_text(json.dumps(dict(failures=6, retry_at=2000)))
            backoff = mac_pool.RestartBackoff(path)
            with mock.patch.object(mac_pool.time, 'time', return_value=1000), \
                    mock.patch.object(mac_pool.time, 'sleep') as sleep:
                self.assertFalse(backoff.begin(lambda:True))
                sleep.assert_not_called()
            self.assertEqual(json.loads(path.read_text())['failures'], 6)
            with mock.patch.object(mac_pool.time, 'monotonic', return_value=0):
                backoff.tick(dict(slots=[dict(state='ready')]))
            with mock.patch.object(mac_pool.time, 'monotonic', return_value=599):
                backoff.tick(dict(slots=[dict(state='ready')]))
                self.assertTrue(path.exists())
                backoff.tick(dict(slots=[dict(state='failed')]))
                backoff.tick(dict(slots=[dict(state='busy')]))
            with mock.patch.object(mac_pool.time, 'monotonic', return_value=1199):
                backoff.tick(dict(slots=[dict(state='busy')]))
            self.assertFalse(path.exists())
            with mock.patch.object(mac_pool.time, 'time', return_value=2000):
                self.assertTrue(mac_pool.RestartBackoff(path).begin(lambda:False))
            self.assertEqual(json.loads(path.read_text())['failures'], 1)


class OrphanTransportTests(unittest.TestCase):
    def reap(self, record, commands):
        killed = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'transports.json'; path.write_text(json.dumps(record))
            with mock.patch.object(mac_pool, 'process_command', side_effect=lambda pid: commands.get(pid)), \
                    mock.patch.object(mac_pool.os, 'killpg', side_effect=lambda pid, sig: killed.append((pid, sig))), \
                    mock.patch.object(mac_pool, 'transport_group_running', return_value=False):
                reaped = mac_pool.reap_orphan_transports(path, grace_seconds=0)
            return reaped, killed, path.exists()

    def test_dead_owner_transports_are_reaped_but_reused_pids_are_kept(self):
        record = dict(owner=10, ownerCommand='python mac-pool.py', groups=[
            dict(pid=11, command='mac-relay /key'), dict(pid=12, command='cloudflared tunnel')])
        reaped, killed, kept = self.reap(record, {11: 'mac-relay /key', 12: 'some other program'})
        self.assertEqual(reaped, [11]); self.assertEqual(killed, [(11, signal.SIGTERM)]); self.assertFalse(kept)

    def test_live_owner_refuses_start(self):
        record = dict(owner=10, ownerCommand='python mac-pool.py', groups=[dict(pid=11, command='mac-relay /key')])
        with self.assertRaises(RuntimeError):
            self.reap(record, {10: 'python mac-pool.py', 11: 'mac-relay /key'})

    def test_group_of_dead_leader_is_reaped(self):
        record = dict(owner=10, ownerCommand='python mac-pool.py', groups=[dict(pid=11, command='cloudflared tunnel')])
        with mock.patch.object(mac_pool, 'transport_group_running', side_effect=__import__('itertools').chain([True], __import__('itertools').repeat(False))):
            killed = []
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/'transports.json'; path.write_text(json.dumps(record))
                with mock.patch.object(mac_pool, 'process_command', return_value=None), \
                        mock.patch.object(mac_pool.os, 'killpg', side_effect=lambda pid, sig: killed.append(pid)):
                    reaped = mac_pool.reap_orphan_transports(path, grace_seconds=0)
        self.assertEqual((reaped, killed), ([11], [11]))


class GuestDirectoryTests(unittest.TestCase):
    def snapshot(self):
        return {'slots': [{'state': 'ready', 'attestation': {
            'relay_peer': 'guest', 'admit_until': 1500,
            'payments': {'runExpires': 1800}}}]}

    def test_heartbeat_and_busy_state_do_not_repeat_chain_transaction(self):
        snapshot = self.snapshot()
        hint = {'url': 'wss://guest.trycloudflare.com/', 'relayPeer': 'relay', 'expiresAt': 2000}
        publish = Mock()
        entries = mac_pool.guest_entries(snapshot, hint, now=1000)
        previous = mac_pool.publish_directory(publish, entries, None)
        hint['expiresAt'] += 60
        snapshot['slots'][0]['state'] = 'busy'
        previous = mac_pool.publish_directory(publish, mac_pool.guest_entries(snapshot, hint, now=1060), previous)
        publish.assert_called_once_with(entries, True)
        self.assertEqual(entries[0]['expiresAt'], 1500)
        self.assertEqual(entries[0]['guestPeer'], 'guest')
        changed = dict(hint, url='wss://replacement.trycloudflare.com/')
        previous = mac_pool.publish_directory(publish, mac_pool.guest_entries(snapshot, changed, now=1060), previous)
        self.assertEqual(publish.call_count, 2)
        previous = mac_pool.publish_directory(publish, mac_pool.guest_entries(snapshot, changed, now=1500), previous)
        self.assertEqual(publish.call_args.args, ([], True))
        self.assertEqual(previous, [])

    def test_local_guest_removal_and_publication_failure_do_not_need_broker(self):
        hint = {'url': 'wss://guest.trycloudflare.com/', 'relayPeer': 'relay'}
        entries = mac_pool.guest_entries(self.snapshot(), hint, now=1000)
        publish = Mock(side_effect=[subprocess.CalledProcessError(1, ['chain']), None, None])
        with contextlib.redirect_stdout(io.StringIO()):
            previous = mac_pool.publish_directory(publish, entries, None)
            self.assertIsNone(previous)
            previous = mac_pool.publish_directory(publish, entries, previous)
        self.assertEqual(previous, entries)
        removed = mac_pool.guest_entries({'slots': []}, hint, now=1100)
        self.assertEqual(mac_pool.publish_directory(publish, removed, previous), [])
        self.assertEqual(publish.call_count, 3)


    def test_startup_and_repeated_empty_directory_do_not_submit_transactions(self):
        publish = Mock()
        previous = mac_pool.publish_directory(publish, [], [])
        self.assertEqual(mac_pool.publish_directory(publish, [], previous), [])
        publish.assert_not_called()

    def test_pending_attempt_survives_retry_and_new_entries_wait_for_its_receipt(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pending = root/'pending.txt'
            prepared = []
            def prepare(entries):
                out = root/str(len(prepared)); out.mkdir()
                (out/'entries.json').write_text(json.dumps(entries))
                prepared.append(out)
                return out
            accepted = []
            def first_attempt(out):
                (out/'publish-transaction.json').write_text('{"hash":"0xaccepted"}')
                accepted.append(out)
                raise subprocess.CalledProcessError(1, ['publication'])
            old, new = [{'guestPeer': 'old'}], [{'guestPeer': 'new'}]
            with self.assertRaises(subprocess.CalledProcessError):
                mac_pool.publish_chain(old, pending, prepare, first_attempt)
            self.assertEqual(prepared, accepted)
            failed_reconciliation = Mock(side_effect=subprocess.CalledProcessError(1, ['reconcile']))
            with self.assertRaises(subprocess.CalledProcessError):
                mac_pool.publish_chain(new, pending, prepare, failed_reconciliation)
            self.assertEqual(prepared, accepted)
            failed_reconciliation.assert_called_once_with(accepted[0])
            recovered = []
            mac_pool.publish_chain(new, pending, prepare, recovered.append)
            self.assertEqual(recovered, [accepted[0], prepared[1]])
            self.assertEqual(json.loads((prepared[0]/'entries.json').read_text()), old)
            self.assertEqual(json.loads((prepared[1]/'entries.json').read_text()), new)
            self.assertFalse(pending.exists())


PEER = '12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x'


@contextlib.contextmanager
def transport_server(responses, peer=PEER):
    requests = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            status = responses[min(len(requests)-1, len(responses)-1)]
            if status is None:
                self.close_connection = True
                return
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            try:
                self.wfile.write(json.dumps({'peer_id': peer} if status == 200 else
                                            {'private_error': 'response body must stay private'}).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass  # The deadline case deliberately closes a request early.

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port), requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class TransportDiscoveryTests(unittest.TestCase):
    def test_transient_http_and_closed_connection_retry_to_valid_peer(self):
        for status in (408, 429, 500, 503, None):
            with self.subTest(status=status), transport_server([status, 200]) as (url, requests):
                log = io.StringIO()
                with contextlib.redirect_stdout(log):
                    self.assertEqual(mac_pool.discover_transport(url, retry_seconds=.01), PEER)
                self.assertEqual(requests, ['/sandbox/transport', '/sandbox/transport'])
                event = json.loads(log.getvalue())
                self.assertEqual(event['status'], status)
                self.assertNotIn('response body must stay private', log.getvalue())

    def test_permanent_http_refusal_is_not_retried(self):
        with transport_server([403, 200]) as (url, requests):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                mac_pool.discover_transport(url, retry_seconds=.01)
            self.assertEqual(len(requests), 1)

    def test_invalid_peer_is_not_retried(self):
        with transport_server([200], peer='untrusted invalid peer') as (url, requests):
            with self.assertRaisesRegex(ValueError, 'invalid Ed25519 peer'):
                mac_pool.discover_transport(url, retry_seconds=.01)
            self.assertEqual(len(requests), 1)

    def test_transport_outage_has_a_deadline(self):
        # Scheduling a local HTTP server must not consume the retry budget.
        clock = [0.0]
        timeouts = []
        def unavailable(url, timeout):
            timeouts.append(timeout)
            clock[0] += .25  # Account for time spent in the request itself.
            raise mac_pool.URLError('offline')
        def sleep(seconds):
            clock[0] += seconds
        with mock.patch.object(mac_pool.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(mac_pool.time, 'sleep', side_effect=sleep), \
                mock.patch.object(mac_pool, 'urlopen', side_effect=unavailable), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'unavailable after'):
                mac_pool.discover_transport('http://broker', budget_seconds=3, retry_seconds=1)
        self.assertEqual(timeouts, [3, 1.75, .5])
        self.assertEqual(clock[0], 3)

    def test_stop_skips_further_requests(self):
        with transport_server([503]) as (url, requests), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'stopped during'):
                mac_pool.discover_transport(url, stopped=lambda: bool(requests), retry_seconds=.01)
            self.assertEqual(len(requests), 1)


class OwnedTransportCleanupTests(unittest.TestCase):
    def test_guest_shutdown_timeout_still_stops_transports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pools = Mock(stop=Mock(side_effect=subprocess.TimeoutExpired('drain', 4300)))
            with mock.patch.object(mac_pool, 'stop_transports', return_value=[123]) as stop:
                with self.assertRaises(subprocess.TimeoutExpired):
                    mac_pool.finish(pools, False, [], root/'pending', Mock(), [Mock()], [], [], root)
                stop.assert_called_once()

    def test_withdrawal_refusal_is_logged_and_does_not_fail_shutdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            publish = Mock(side_effect=subprocess.CalledProcessError(1, ['broker', 'HTTP 400 stale publisher update']))
            with mock.patch.object(mac_pool, 'stop_transports', return_value=[]) as stop, \
                    contextlib.redirect_stdout(io.StringIO()) as log:
                mac_pool.finish(None, True, [], root/'pending', publish, [], [], [], root)
            publish.assert_called_once_with([], False)
            self.assertIn('periodic-publication-failed', log.getvalue())
            stop.assert_called_once_with([])

    def test_startup_failure_reaps_the_already_started_relay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workload = root/'workload'; workload.mkdir()
            (workload/'compose-manifest.json').write_text(json.dumps(dict(docker_compose_file=json.dumps(dict(
                services=dict(node=dict(environment=dict(HTTPS_PROXY='http://127.0.0.1:18484'),
                                        command=['serve', '/p2p/expected'])))))))
            relay = root/'relay'
            relay.write_text('#!'+sys.executable+"\nimport time\nprint('relay_peer=12D3KooWwrong',flush=True)\ntime.sleep(120)\n")
            relay.chmod(0o755)
            args = ['mac-pool.py', '--state', str(root/'pool-one'), '--runner', str(root), '--workload', str(workload),
                    '--relay', str(relay), '--relay-key', str(relay), '--cloudflared', str(relay),
                    '--publisher-key', str(relay), '--publisher-address', 'publisher', '--registry', 'registry', '--browse-upstream', '127.0.0.1:18889',
                    '--broker', 'https://broker.test', '--index', 'https://broker.test/tunnels', '--pool-version', 'test']
            with mock.patch.object(sys, 'argv', args), mock.patch.object(mac_pool, 'operator_config'), \
                    mock.patch.object(mac_pool, 'hardware'), mock.patch.object(mac_pool, 'measured_size'), \
                    mock.patch.object(mac_pool, 'release_config'), mock.patch.object(mac_pool, 'preflight'), \
                    mock.patch.object(mac_pool, 'discover_transport', return_value=PEER), \
                    mock.patch.object(mac_pool.signal, 'signal'):
                with self.assertRaisesRegex(ValueError, 'relay key does not match'):
                    mac_pool.main()
            stopped = json.loads((root/'pool-one/stopped.json').read_text())
            self.assertTrue(stopped['ownedChildrenStopped'])
            self.assertTrue(stopped['ownedTransportGroupsStopped'])
            for pid in stopped['pids']:
                self.assertFalse(mac_pool.transport_group_running(pid))

    def test_interrupted_pin_publication_reaps_its_owned_group_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'pin-state'
            (state / 'repo').mkdir(parents=True)
            (state / 'repo/config').write_text(json.dumps({'Addresses': {}, 'Swarm': {'ConnMgr': {}}, 'Datastore': {}}))
            ipfs = root / 'ipfs-fixture'
            ipfs.write_text('#!' + sys.executable + "\n" + r'''
import json,os,signal,subprocess,sys,time
from pathlib import Path
args=sys.argv[1:]
state=Path(os.environ['IPFS_PATH']).parent
if args[:2]==['key','list']:print('fixture-key friends-page')
elif args[0]=='daemon':
 print('Daemon is ready',flush=True)
 time.sleep(120)
elif args[:2]==['dag','import']:
 print(json.dumps({'Root':{'Cid':{'/':'fixture-cid'}}}))
elif args[:2]==['name','publish']:
 child=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(120)'],stdout=subprocess.DEVNULL)
 (state/'descendant.pid').write_text(str(child.pid))
 time.sleep(120)
''')
            ipfs.chmod(0o755)
            tunnel = root / 'tunnel-fixture'
            tunnel.write_text('#!' + sys.executable + "\nimport time\nprint('https://pin-fixture.trycloudflare.com',flush=True)\ntime.sleep(120)\n")
            tunnel.chmod(0o755)
            script = Path(__file__).resolve().parents[1] / 'private-agent-web/pin-mac.py'
            with (root / 'pin.log').open('w') as log:
                proc = subprocess.Popen([sys.executable, str(script), '--ipfs', str(ipfs), '--cloudflared', str(tunnel),
                                         '--car', str(root / 'page.car'), '--state', str(state)],
                                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    deadline = time.monotonic() + 10
                    while not (state / 'descendant.pid').exists() and proc.poll() is None and time.monotonic() < deadline:
                        time.sleep(.02)
                    self.assertTrue((state / 'descendant.pid').exists(), (root / 'pin.log').read_text())
                    groups = mac_pool.stop_transports([proc], grace_seconds=1)
                    self.assertEqual(groups, [proc.pid])
                    self.assertFalse(mac_pool.transport_group_running(proc.pid))
                    self.assertTrue(json.loads((state / 'stopped.json').read_text())['retainedRecursivePin'])
                    descendant = int((state / 'descendant.pid').read_text())
                    status = subprocess.run(['ps', '-p', str(descendant), '-o', 'stat='], capture_output=True, text=True)
                    self.assertTrue(status.returncode != 0 or status.stdout.strip().startswith('Z'))
                finally:
                    if mac_pool.transport_group_running(proc.pid):
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
