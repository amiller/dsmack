"""Exercise actual selected base validator, no alternate native path allowance."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'base-vm/browser-sandbox-v1/source/runner-content/lib'))
from dsmack_compose_contract.manifest import _validate_allowed_files
from audit_stage import SLOTS

class NativeTargets(unittest.TestCase):
    def test_native_inputs_targets_and_rejected_public_alias(self):
        for root,expected in [('/workspace/inputs',False),('/workspace/public',True)]:
            files=[{'slot':name.replace('_','-'),'target':root+'/'+name,'max_bytes':16777216,'mode':'ro','required':True,'audience':'workload'}for name in SLOTS]
            errors=[];_validate_allowed_files(files,None,errors)
            self.assertEqual(bool(errors),expected)
        self.assertIn("public=Path('/workspace/inputs')",(Path(__file__).with_name('entrypoint.py')).read_text())

if __name__=='__main__':unittest.main()
