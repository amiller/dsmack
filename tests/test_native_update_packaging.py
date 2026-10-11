import datetime as dt
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
archive = load('native_update_archive')
recommend = load('native_update_recommendation')

class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.app = self.root / 'Node.app'
        for name in ['Contents/MacOS','Contents/Resources']:(self.app / name).mkdir(parents=True, exist_ok=True)
        (self.app / 'Contents/MacOS/node').write_bytes(b'fixture, not executable')
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion':'5','CFBundleShortVersionString':'1.2.3'}))
        self.network = {k:k for k in ['chainId','registry','category','protocolVersion','relay','rpc','peer','badges','accountFactory']}
        (self.app / 'Contents/Resources/dsmack-release.json').write_text(json.dumps({'format':1,'profile':'native-v2','build':5,'version':'1.2.3','sourceCommit':'a'*40,'network':self.network}))
        self.zip = self.root / 'Node.zip'
        self.now = dt.datetime(2026,10,11,tzinfo=dt.timezone.utc)
    def make(self, **overrides):
        args = dict(archive=self.zip,tag='native-v1.2.3',expiry='2026-10-12T00:00:00Z',previous=[4],rollback=[],evidence='https://github.com/amiller/dsmack/pull/1',now=self.now)
        args.update(overrides); return recommend.recommendation(**args)
    def test_packaged_bytes_generate_matching_recommendation(self):
        archive.package(self.app,self.zip); result=self.make()
        self.assertEqual(result['bytes'],self.zip.stat().st_size); self.assertEqual(result['network'],self.network)
        with zipfile.ZipFile(self.zip) as z:
            self.assertEqual(len(z.infolist()),3)
            self.assertTrue(all(not i.extra and i.filename.startswith('Node.app/') for i in z.infolist()))
        with self.assertRaises(FileExistsError):archive.package(self.app,self.zip)
    def test_symlink_rejected_before_archive(self):
        (self.app/'Contents/escape').symlink_to('/tmp')
        with self.assertRaises(ValueError):archive.package(self.app,self.zip)
        self.assertFalse(self.zip.exists())
    def test_expired_wrong_previous_or_path_tag_refused(self):
        archive.package(self.app,self.zip)
        for bad in [dict(expiry='2026-10-10T00:00:00Z'),dict(previous=[5]),dict(tag='../escape'),dict(evidence='https://example.com/review')]:
            with self.assertRaises(ValueError):self.make(**bad)
    def test_signed_metadata_version_conflict_refused(self):
        (self.app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion':'6','CFBundleShortVersionString':'1.2.3'}))
        archive.package(self.app,self.zip)
        with self.assertRaises(ValueError):self.make()

if __name__ == '__main__':unittest.main()
