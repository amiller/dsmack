"""Detect valid timestamp cache substitution in the internal join loader.
Run after copying this test beside join-original.py in the reviewed source tree.
Only synthetic temporary source/cache and a local marker are created.
"""
import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

class JoinSourceLoading(unittest.TestCase):
    def test_valid_cache_executes_in_standard_loader_but_not_selected_join(self):
        here = Path(__file__).resolve().parent
        original = here.parent / 'bounty-judges' / 'closure.py'
        with tempfile.TemporaryDirectory(prefix='dsmack-join-cache-test-') as td:
            root = Path(td)
            app = root / 'applications'
            settle = app / 'bounty-settlement'
            judges = app / 'bounty-judges'
            settle.mkdir(parents=True)
            judges.mkdir()
            join = settle / 'join-original.py'
            shutil.copyfile(here / 'join-original.py', join)
            target = judges / 'closure.py'
            good = original.read_bytes()
            marker = root / 'unexpected-cache-execution'
            evil = ('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("cache executed")\n').encode()
            self.assertLess(len(evil), len(good))
            evil += b'#' * (len(good) - len(evil))
            target.write_bytes(evil)
            fixed_time = 1700000000
            os.utime(target, (fixed_time, fixed_time))
            py_compile.compile(str(target), doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            target.write_bytes(good)
            os.utime(target, (fixed_time, fixed_time))
            # Establish the negative fixture really can execute under -I -B.
            baseline = ('import importlib.util; p=' + repr(str(target)) + ';'
                        's=importlib.util.spec_from_file_location("cached_control",p);'
                        'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)')
            result = subprocess.run([sys.executable, '-I', '-B', '-c', baseline],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(marker.exists(), 'control must actually execute planted cache')
            marker.unlink()
            result = subprocess.run([sys.executable, '-I', '-B', str(join)],
                                    input=b'{}', capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2, 'original source rejects incomplete input')
            self.assertFalse(marker.exists(), 'selected join must ignore valid cache')
            self.assertEqual(result.stderr, b'closed acceptance join refused\n')

if __name__ == '__main__':
    unittest.main()
