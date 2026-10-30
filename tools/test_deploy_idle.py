import unittest
from deploy_idle import wait_for_idle


class IdleGuardTest(unittest.TestCase):
    def test_waits_for_both_guest_and_stream(self):
        at = [0]
        reads = []
        def read(path):
            reads.append(path)
            return {'totals': {'busy_slots': int(at[0] < 2)}} if path == '/network' else {'inFlightStreams': int(at[0] < 4)}
        wait_for_idle('unused', read=read, clock=lambda: at[0], sleep=lambda seconds: at.__setitem__(0, at[0] + seconds))
        self.assertEqual(at[0], 4)
        self.assertEqual(len(reads), 6)

    def test_busy_timeout_prevents_deploy(self):
        def read(path):
            return {'totals': {'busy_slots': 0}} if path == '/network' else {'inFlightStreams': 1}
        with self.assertRaisesRegex(RuntimeError, 'no deployment was started'):
            wait_for_idle('unused', 0, read=read)

    def test_missing_activity_is_not_idle(self):
        with self.assertRaisesRegex(RuntimeError, 'must report'):
            wait_for_idle('unused', read=lambda path: {'totals': {'busy_slots': 0}} if path == '/network' else {})


if __name__ == '__main__':
    unittest.main()
