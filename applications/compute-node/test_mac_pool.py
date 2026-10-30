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
            self.assertFalse(mac_pool.republish(publish, hint, False))
            self.assertFalse(mac_pool.republish(publish, hint, True))
            self.assertTrue(mac_pool.republish(publish, hint, True))
        self.assertEqual(publish.call_count, 3)
        events = [json.loads(line) for line in log.getvalue().splitlines()]
        self.assertEqual([event['error'] for event in events], ['CalledProcessError', 'TimeoutExpired'])
        self.assertTrue(all(event['retrySeconds'] == 60 for event in events))

    def test_periodic_publication_does_not_mask_configuration_errors(self):
        with self.assertRaises(ValueError):
            mac_pool.republish(Mock(side_effect=ValueError('invalid publisher key')), {}, False)


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

    def test_transport_outage_has_a_deadline_and_stop_skips_further_requests(self):
        with transport_server([503]) as (url, requests), contextlib.redirect_stdout(io.StringIO()):
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, 'unavailable after'):
                mac_pool.discover_transport(url, budget_seconds=.04, retry_seconds=.01)
            self.assertGreater(len(requests), 1)
            self.assertLess(time.monotonic() - started, 1)
            calls = len(requests)
            with self.assertRaisesRegex(RuntimeError, 'stopped during'):
                mac_pool.discover_transport(url, stopped=lambda: len(requests) > calls, retry_seconds=.01)
            self.assertEqual(len(requests), calls + 1)


class OwnedTransportCleanupTests(unittest.TestCase):
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
