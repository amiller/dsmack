"""Detect classifier regression; fake image module is not an actual image test."""
from pathlib import Path
import json
import subprocess
import sys
import unittest

class DriverExitControls(unittest.TestCase):
    def test_audit_refusal_is_infrastructure_behavioral_exit_is_preserved(self):
        raw=Path(__file__).with_name('driver.py').read_text()
        for body,expected in [('return 0',0),('return 1',1),('raise ValueError("audit refused")',2),('raise ValueError("x"*5000)',2)]:
            script='import sys,types\nm=types.ModuleType("entrypoint")\nm.__file__="/opt/applications/bounty-runtime/entrypoint.py"\nexec('+repr('def main():\n    '+body+'\n')+',m.__dict__)\nsys.modules["entrypoint"]=m\nexec(compile('+repr(raw)+',"/workspace/inputs/driver","exec"),{"__name__":"__main__","__file__":"/workspace/inputs/driver"})\n'
            result=subprocess.run([sys.executable,'-I','-B','-c',script],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,expected,result.stderr)
            if expected==2:
                self.assertLessEqual(len(result.stderr),1024)
                if 'audit refused' in body:self.assertIn(b'ValueError: audit refused',result.stderr)
                self.assertNotIn(b'Traceback',result.stderr)

if __name__=='__main__':unittest.main()
