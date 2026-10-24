"""Prospective serialization controls. Fake CLI only; no provider/browser/VM."""
import copy
import json
from pathlib import Path
import subprocess
import shutil
import unittest
import generate as g
import test_generate as fixtures


def stream_with_raw(raw):
    events = [g.parse(line) for line in fixtures.transcript().splitlines()]
    events[-1]['result'] = raw.decode('utf-8')
    return b'\n'.join(g.canonical(event) for event in events)+b'\n'


class CanonicalizationControls(unittest.TestCase):
    def test_key_order_whitespace_and_escapes_preserve_values_and_arrays(self):
        value = copy.deepcopy(fixtures.SUITE)
        value['tests'][0]['steps'].append({'op':'assert_text','selector':'main','value':'π\ntext'})
        reordered = {'tests':[{'steps':[dict(reversed(list(step.items()))) for step in value['tests'][0]['steps']],
                              'id':value['tests'][0]['id']}], 'schema':value['schema']}
        raw = json.dumps(reordered, indent=2, ensure_ascii=True).encode()
        suite = g.canonicalize_suite(raw)
        self.assertEqual(suite, g.canonical(value))
        self.assertEqual(g.parse(suite), g.parse(raw))
        self.assertEqual(g.canonicalize_suite(suite), suite)
        self.assertFalse(g.suite_serialization_record(raw, suite)['raw_equals_canonical'])

    def test_duplicate_decoded_keys_and_numeric_coercions_refuse(self):
        for raw in (b'{"x":0,"x":1}', b'{"nested":{"op":0,"o\\u0070":1}}',
                    b'{"x":1.0}', b'{"x":1e0}', b'{"x":-0}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":9007199254740992}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                g.canonicalize_suite(raw)
        # Stream observation still accepts ordinary CLI timing floats.
        self.assertEqual(g.parse(b'{"duration":1.5}'), {'duration':1.5})

    def test_malformed_fenced_unicode_and_raw_size_refuse(self):
        for raw in (b'', b'```json\n{}\n```', b'{} trailing', b'{"x":"\xff"}',
                    b'{"x":"\\ud800"}', b'\xef\xbb\xbf{}', b' '*g.MAX_SUITE+b'{}'):
            with self.subTest(raw=raw[:40]), self.assertRaises((ValueError, UnicodeError)):
                g.canonicalize_suite(raw)

    def test_does_not_sort_ids_or_repair_grammar(self):
        value = copy.deepcopy(fixtures.SUITE)
        value['tests'][0]['id'] = 'z-last'
        value['tests'].append(copy.deepcopy(value['tests'][0]))
        value['tests'][1]['id'] = 'a-first'
        suite = g.canonicalize_suite(json.dumps(value, indent=2).encode())
        self.assertEqual([t['id'] for t in g.parse(suite)['tests']], ['z-last','a-first'])
        p = subprocess.run([shutil.which('node'), str(g.HERE/'suite-contract.mjs')], input=suite, capture_output=True)
        self.assertNotEqual(p.returncode, 0)


class RuntimeControls(fixtures.GenerationControls):
    # Includes all original fake-CLI generation/closure/model/budget controls.
    def test_noncanonical_model_result_has_separate_raw_and_measured_suite(self):
        raw = json.dumps({'tests':fixtures.SUITE['tests'],'schema':fixtures.SUITE['schema']}, indent=2).encode()
        original = stream_with_raw(raw);self.make_cli(original)
        checks, outcome = self.run_generate()
        self.assertTrue(checks['completed'], outcome)
        out = self.root/'output-1';suite=(out/'suite.json').read_bytes()
        self.assertEqual((out/'suite-model-raw.txt').read_bytes(), raw)
        self.assertEqual((out/'transcript.jsonl').read_bytes(), original)
        self.assertEqual(suite, g.canonical(fixtures.SUITE))
        self.assertEqual(g.observe(original)[0], raw)  # raw API remains unchanged
        record = g.parse((out/'suite-serialization.json').read_bytes())
        self.assertEqual(record, g.suite_serialization_record(raw, suite))
        self.assertEqual(record['raw_sha256'], g.sha(raw))
        self.assertEqual(record['canonical_sha256'], checks['suite_sha256'])
        self.assertFalse(record['raw_equals_canonical'])

    def test_duplicate_provider_suite_retains_original_without_success(self):
        raw = b'{"schema":"bad",'+g.canonical(fixtures.SUITE)[1:]
        original = stream_with_raw(raw);self.make_cli(original)
        checks, outcome = self.run_generate()
        self.assertFalse(checks['completed'])
        self.assertIn('duplicate JSON key', outcome['error'])
        out=self.root/'output-1'
        self.assertEqual((out/'suite-model-raw.txt').read_bytes(), raw)
        self.assertEqual((out/'transcript.jsonl').read_bytes(), original)
        self.assertFalse((out/'suite.json').exists())
        self.assertFalse((out/'suite-serialization.json').exists())


if __name__ == '__main__':
    unittest.main()
