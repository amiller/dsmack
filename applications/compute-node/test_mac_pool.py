"""A discovery publication outage must not stop a serving Mac pool."""
import contextlib
import importlib.util
import io
import json
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
            self.wfile.write(json.dumps({'peer_id': peer} if status == 200 else
                                        {'private_error': 'response body must stay private'}).encode())

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


if __name__ == '__main__':
    unittest.main()
