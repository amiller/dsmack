import importlib.util, json, plistlib, struct, subprocess, sys, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
archive = load('native_update_archive', 'tools/native_update_archive.py')
sys.path.insert(0, str(ROOT / 'scripts/release'))
publish = load('publish_update', 'scripts/release/publish_update.py')
VECTORS = ROOT / 'contracts/fixtures/measure'

def executable(vector):
    """A file measure.inputs() reads as the fixture's signed executable: page 0, then the signature
    SuperBlob (CodeDirectory, DER entitlements) at LC_CODE_SIGNATURE's dataoff."""
    h = lambda k: bytes.fromhex(vector[k][2:])
    page0, cd, ent = h('page0'), h('cd'), h('ent')
    der = struct.pack('>II', 0xfade7172, len(ent) + 8) + ent
    blob = struct.pack('>III', 0xfade0cc0, 12 + 16 + len(cd) + len(der), 2) + struct.pack('>IIII', 0, 28, 7, 28 + len(cd)) + cd + der
    dataoff = struct.unpack_from('<I', page0, vector['codeSigCmd'] + 8)[0]
    return page0 + bytes(dataoff - len(page0)) + blob

class PublishUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
    def package(self, name, version='0.2.1'):
        app = self.root / name / 'Node.app'
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/MacOS/node').write_bytes(executable(json.loads((VECTORS / f'{name}.json').read_text())))
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': version}))
        out = self.root / name / 'Dsmack-Node-0.2.1.zip'; archive.package(app, out); return out
    def test_two_teams_one_measurement_modified_another(self):
        summary = json.loads((VECTORS / 'summary.json').read_text())
        feeds = {n: publish.feed(self.package(n), 'node-v0.2.1', 'notes') for n in ['honest-a', 'honest-b', 'modified']}
        for n, f in feeds.items():
            self.assertEqual(f['M'], summary[n]['M'])
            self.assertEqual(set(f), {'version', 'tag', 'url', 'sha256', 'M', 'notes'})
        self.assertEqual(feeds['honest-a']['M'], feeds['honest-b']['M'])
        self.assertNotEqual(feeds['honest-a']['sha256'], feeds['honest-b']['sha256'])
        self.assertEqual(feeds['honest-a']['url'], 'https://github.com/amiller/dsmack/releases/download/node-v0.2.1/Dsmack-Node-0.2.1.zip')
    def test_cli_writes_feed(self):
        out = self.root / 'updates.json'
        subprocess.run([sys.executable, str(ROOT / 'scripts/release/publish_update.py'), '--archive', str(self.package('honest-a')),
                        '--tag', 'node-v0.2.1', '--output', str(out)], check=True, capture_output=True)
        self.assertEqual(json.loads(out.read_text())['version'], '0.2.1')
    def test_bad_tag_or_version_refused(self):
        zip_ = self.package('honest-a', version='0.2.0')
        for tag in ['node-v0.2.1', 'native-v0.2.0', 'node-v0.2.0-rc.1']:
            with self.assertRaises(ValueError): publish.feed(zip_, tag, '')
    def test_packager_bounds(self):
        zip_ = self.package('honest-a')
        with zipfile.ZipFile(zip_) as z:
            self.assertTrue(all(not i.extra and i.filename.startswith('Node.app/') for i in z.infolist()))
        with self.assertRaises(FileExistsError): archive.package(self.root / 'honest-a/Node.app', zip_)
        (self.root / 'honest-a/Node.app/Contents/escape').symlink_to('/tmp')
        with self.assertRaises(ValueError): archive.package(self.root / 'honest-a/Node.app', self.root / 'other.zip')

if __name__ == '__main__': unittest.main()
