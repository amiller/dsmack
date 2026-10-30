"""A discovery publication outage must not stop a serving Mac pool."""
import contextlib
import importlib.util
import io
import json
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


if __name__ == '__main__':
    unittest.main()
