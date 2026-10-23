import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('diagnostic', Path(__file__).with_name('diagnose_generation_reliability.py'))
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)

class Controls(unittest.TestCase):
    def test_fragmented_safe_arrivals(self):
        now = [0.0]
        e = d.EventTimings(lambda: now[0])
        raw = json.dumps(dict(type='system', subtype='init', model=d.MODEL, secret='CANARY')).encode()+b'\n'
        now[0] = .125
        for value in raw:
            e.feed(bytes([value]))
        now[0] = .250
        e.feed(json.dumps(dict(type='assistant', message=dict(model=d.MODEL, content='CANARY'))).encode()+b'\n')
        now[0] = .500
        e.feed(b'{"type":"result","result":"CANARY"}\n')
        self.assertEqual(e.summary()['first_event_elapsed_ms'], dict(init=125, assistant=250, result=500))
        self.assertNotIn('CANARY', json.dumps(e.summary()))

    def test_parse_and_size_bounds(self):
        e = d.EventTimings()
        e.feed(b'{"type":"result","type":"assistant"}\n')
        e.feed(b'x'*262145+b'\n{"type":"result"}\n')
        self.assertEqual(e.counts['parse_refused'], 2)
        self.assertEqual(e.counts['result'], 1)
        for _ in range(1030): e.feed(b'{"type":"result"}\n')
        self.assertTrue(e.event_bound_hit)
        self.assertEqual(sum(e.counts.values()), 1024)

    def run_child(self, code, seconds=2, cap=4096):
        with tempfile.TemporaryDirectory() as root:
            return d.timed_process([sys.executable, '-I', '-c', code], b'', root, {}, seconds, cap, cap, d.EventTimings())

    def test_process_success_and_bounds(self):
        raw, err, status, failure = self.run_child('print(\'{"type":"result"}\')')
        self.assertEqual((status, failure), (0, None))
        self.assertEqual(err, b'')
        self.assertIn(b'result', raw)
        raw, _, _, failure = self.run_child('print("x"*5000)', cap=16)
        self.assertEqual((len(raw), failure), (16, 'output bound'))
        _, err, _, failure = self.run_child('import sys; sys.stderr.write("x"*5000)', cap=16)
        self.assertEqual((len(err), failure), (16, 'output bound'))

    def test_deadline_reaps_child(self):
        _, _, status, failure = self.run_child('import time; time.sleep(30)', seconds=.05)
        self.assertEqual(failure, 'deadline')
        self.assertLess(status, 0)

    def test_image_source_pin(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'generate.py'
            path.write_text('raise RuntimeError("must not execute")')
            with patch.object(d, 'GENERATOR', path):
                with self.assertRaises(ValueError): d.image_generator()

    def wrapper_case(self, flat=False, refuse=False):
        with tempfile.TemporaryDirectory() as root:
            state, output = Path(root)/'state', Path(root)/'output'
            state.mkdir(); output.mkdir()
            (Path(root)/'base.json').write_bytes(b'BASE')
            (Path(root)/'spec.txt').write_bytes(b'SPEC')
            (Path(root)/'driver').write_bytes(b'EXTRA-MEASURED-DRIVER')
            q = types.SimpleNamespace(WALL_SECONDS=180, MAX_TURNS=2, CLI_SHA256='pin',
                MAX_STDOUT=1048576, MAX_STDERR=65536, MAX_INPUT=524288, file_sha=lambda _: 'pin',
                read_regular=lambda path, bound: path.read_bytes(),
                load_snapshot=lambda *args: ('base', 'spec', 'unused'),
                prompt=lambda *args: 'EXACTPROMPT',
                cli_command=lambda *args: ['exact', 'EXACTPROMPT'],
                bounded_process=lambda *args: (b'version', b'', 0, None))
            def load_snapshot(public, snapshot, base):
                if flat:
                    self.assertEqual(sorted(p.name for p in public.iterdir()), ['base.json', 'spec.txt'])
                    self.assertEqual((public/'base.json').read_bytes(), b'BASE')
                    self.assertEqual((public/'spec.txt').read_bytes(), b'SPEC')
                    self.assertEqual((public/'base.json').stat().st_mode & 0o777, 0o400)
                return 'base', 'spec', 'unused'
            q.load_snapshot = load_snapshot
            def generate(public, private, cli, model, judge, snapshot, base):
                load_snapshot(public, snapshot, base)
                self.assertEqual(q.WALL_SECONDS, 480)
                self.assertEqual(q.MAX_TURNS, 2)
                private.mkdir()
                (private/'transcript').write_text('CANARY')
                if refuse: raise ValueError('PRIVATE-CANARY-REFUSAL')
                self.assertEqual(q.bounded_process([str(d.CLI), '--version'], b'', state, {}, 10, 4096, 4096)[0], b'version')
                q.bounded_process(['exact', 'EXACTPROMPT'], b'', state, {}, 480, q.MAX_STDOUT, q.MAX_STDERR)
                return {'completed': False}, {'status': 'failed', 'error': 'CLI deadline', 'exit_code': -9}
            q.generate = generate
            def process(*args):
                args[-1].feed(b'{"type":"system","subtype":"init","model":"claude-opus-4-8","secret":"CANARY"}\n')
                return b'CANARY', b'CANARY', -9, 'deadline'
            def paths(value):
                return state if str(value) == '/workspace/state' else Path(value)
            with patch.object(d, 'Path', paths), patch.object(d.os, 'getuid', return_value=1000), patch.object(d.os, 'getgid', return_value=1000), patch.object(d, 'image_generator', return_value=q), patch.object(d, 'timed_process', side_effect=process):
                if refuse:
                    with self.assertRaises(ValueError): d.diagnose(Path(root), 'snapshot', output, flat)
                    self.assertEqual(list(state.iterdir()), [])
                    self.assertEqual(list(output.iterdir()), [])
                    return
                report = d.diagnose(Path(root), 'snapshot', output, flat)
            self.assertEqual(list(state.iterdir()), [])
            self.assertEqual([p.name for p in output.iterdir()], ['generation-reliability.json'])
            self.assertNotIn('CANARY', (output/'generation-reliability.json').read_text())
            self.assertEqual(report['result_category'], 'deadline_after_init')
            self.assertFalse(report['bounty_acceptance'])
            self.assertFalse(report['retry_performed'])

    def test_wrapper_removes_raw_and_whitelists_report(self):
        self.wrapper_case()

    def test_flat_snapshot_excludes_extra_driver_and_cleans_copies(self):
        self.wrapper_case(flat=True)

    def test_flat_copies_cleaned_on_refusal(self):
        self.wrapper_case(flat=True, refuse=True)

if __name__ == '__main__': unittest.main()
