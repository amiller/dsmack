"""End to end on zed Docker with the fake CLI. Needs DSMACK_DISPATCH_CREDENTIAL, a key file path on zed."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_find import FAKE_CLI

CLI = Path(__file__).parent/'skill'/'dsmack-agent'


@unittest.skipUnless(os.environ.get('DSMACK_DISPATCH_CREDENTIAL'), 'needs zed and a key file path on it')
class DispatchTest(unittest.TestCase):
    def test_fake_edit_patch_applies(self):
        tmp = Path(tempfile.mkdtemp())
        repo = tmp/'repo'
        (repo/'src').mkdir(parents=True)
        (repo/'src'/'a.py').write_text('def f():\n    return 1\n')
        git = lambda *a: subprocess.run(['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@t', *a], check=True)
        git('init', '-q')
        git('add', '-A')
        git('commit', '-qm', 'toy')
        fake = tmp/'claude'
        fake.write_text(FAKE_CLI.replace('MODE', 'edit'))
        fake.chmod(0o755)
        out = tmp/'out'
        patch = subprocess.run([str(CLI), 'run', '--repo', str(repo), '--prompt', 'Make f return 2.', '--out', str(out),
                                '--credential', os.environ['DSMACK_DISPATCH_CREDENTIAL'], '--fake-cli', str(fake)],
                               check=True, capture_output=True, text=True).stdout.strip()
        record = json.loads((out/'turn.json').read_text())
        self.assertEqual((record['state_out'], record['verdict'], len(record['transcripts'])), (None, None, 1))
        git('apply', patch)
        self.assertEqual((repo/'src'/'a.py').read_text(), 'def f():\n    return 2\n')
        self.assertEqual((repo/'NOTES.md').read_text(), 'f returns 2\n')


if __name__ == '__main__':
    unittest.main()
