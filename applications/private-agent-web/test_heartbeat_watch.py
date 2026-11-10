from pathlib import Path
import runpy
import tempfile
import unittest

Watch = runpy.run_path(str(Path(__file__).with_name('heartbeat-watch.py')))['Watch']


class HeartbeatTests(unittest.TestCase):
    def test_missing_ping_alerts_after_deadline_across_restart_and_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)/'state.json'; alerts = []; now = [1000]
            watch = Watch(state, alerts.append, lambda: now[0])
            watch.tick(); self.assertEqual(alerts, [])  # Not armed before cron installation.
            watch.ping('staging/capacity')
            now[0] += 180; watch.tick(); self.assertEqual(alerts, [])
            watch = Watch(state, alerts.append, lambda: now[0])
            now[0] += 1; watch.tick(); self.assertEqual(len(alerts), 1)
            self.assertTrue(watch.checks['staging/capacity']['alerted'])
            watch.ping('staging/capacity'); watch.tick()
            self.assertEqual(len(alerts), 2)
            self.assertLessEqual(alerts[-1]['endsAt'], alerts[0]['endsAt'])
            self.assertFalse(watch.checks['staging/capacity']['alerted'])

    def test_alertmanager_error_keeps_the_missed_heartbeat_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = [1000]; alerts = []
            def failed(_): raise OSError('Alertmanager unavailable')
            watch = Watch(Path(tmp)/'state.json', failed, lambda: now[0])
            watch.ping('staging-proof/directory'); now[0] += 421
            with self.assertRaisesRegex(OSError, 'Alertmanager unavailable'): watch.tick()
            self.assertFalse(watch.checks['staging-proof/directory']['alerted'])
            watch.notify = alerts.append; watch.tick()
            self.assertEqual(len(alerts), 1)
