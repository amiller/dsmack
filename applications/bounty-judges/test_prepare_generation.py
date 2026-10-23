import importlib.util
from pathlib import Path
import tempfile
import unittest

import generate as g

spec = importlib.util.spec_from_file_location('prepare_generation', Path(__file__).with_name('prepare-generation.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PreparationControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root/'base'
        (self.base/'apps/board').mkdir(parents=True)
        for name in p.SELECTED:
            (self.base/name).write_text('pinned base '+name)
            (self.base/name).chmod(0o644)
        self.manifest = self.root/'base.manifest.json'
        self.rows = p.scan_tree(self.base)
        self.manifest.write_bytes(g.canonical(self.rows))
        self.tree = p.tree_digest(self.rows)
        self.spec = self.root/'spec.txt'; self.spec.write_text('pinned task specification')
        self.spec_digest = g.sha(self.spec.read_bytes())

    def prepare(self, name='public', **kwargs):
        return p.prepare(self.base, self.manifest, self.spec, kwargs.get('tree', self.tree),
                         kwargs.get('spec', self.spec_digest), self.root/name)

    def test_projection_has_exact_base_and_spec_bytes_and_independent_pins(self):
        result = self.prepare()
        self.assertEqual(sorted(f.name for f in (self.root/'public').iterdir()), ['base.json','spec.txt'])
        base, spec, snapshot = g.load_snapshot(self.root/'public', result['snapshot_sha256'], self.tree)
        self.assertEqual(spec, self.spec.read_bytes())
        self.assertEqual(g.sha(g.canonical(snapshot)), result['snapshot_sha256'])
        self.assertEqual(g.parse(base)['files'], [{'path': name, 'content': (self.base/name).read_text()} for name in p.SELECTED])

    def test_wrong_tree_spec_or_modified_base_refuse_before_output(self):
        for name, kwargs in [('tree', {'tree':'0'*64}), ('spec', {'spec':'0'*64})]:
            with self.assertRaises(ValueError):
                self.prepare(name, **kwargs)
            self.assertFalse((self.root/name).exists())
        (self.base/p.SELECTED[0]).write_text('candidate substituted for base')
        with self.assertRaisesRegex(ValueError, 'differs from admitted manifest'):
            self.prepare()

    def test_extra_file_or_source_symlink_refuse(self):
        (self.base/'candidate.js').write_text('unadmitted source')
        (self.base/'candidate.js').chmod(0o644)
        with self.assertRaises(ValueError):
            self.prepare('extra')
        (self.base/'candidate.js').unlink()
        (self.base/'link').symlink_to(self.spec)
        with self.assertRaises(ValueError):
            self.prepare('link')


if __name__ == '__main__':
    unittest.main()
