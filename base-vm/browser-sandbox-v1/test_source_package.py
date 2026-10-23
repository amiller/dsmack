import hashlib,importlib.util,json,os,pathlib,tempfile,unittest
from unittest.mock import patch
here=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('base_deriver',here/'derive.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);(self.root/'source').mkdir();self.file=self.root/'source/test.py';self.file.write_text('example=1\n');self.lock={'schema':'dsmack-base-vm-source-lock/1','files':{'source/test.py':{'bytes':self.file.stat().st_size,'sha256':d.digest(self.file)}}};self.pin=self.write_lock();self.patcher=patch.object(d,'HERE',self.root);self.patcher.start();self.addCleanup(self.patcher.stop)
 def write_lock(self):
  raw=json.dumps(self.lock,sort_keys=True).encode();(self.root/'SOURCE-LOCK.json').write_bytes(raw);return hashlib.sha256(raw).hexdigest()
 def test_selected_source(self):self.assertEqual(d.source_check(self.pin),self.lock)
 def test_wrong_lock(self):
  with self.assertRaises(ValueError):d.source_check('0'*64)
 def test_changed_source(self):
  self.file.write_text('example=2\n')
  with self.assertRaises(ValueError):d.source_check(self.pin)
 def test_extra_source(self):
  (self.root/'source/extra.py').write_text('')
  with self.assertRaises(ValueError):d.source_check(self.pin)
 def test_missing_source(self):
  self.file.unlink()
  with self.assertRaises(ValueError):d.source_check(self.pin)
 def test_source_link(self):
  f=self.root/'source/extra.py';f.symlink_to(self.file)
  with self.assertRaises(ValueError):d.source_check(self.pin)
 def test_source_fifo(self):
  os.mkfifo(self.root/'source/extra')
  with self.assertRaises(ValueError):d.source_check(self.pin)
 def test_wrong_input_pin(self):
  with self.assertRaises(ValueError):d.regular(self.file,{'bytes':self.file.stat().st_size,'sha256':'0'*64})
 def test_input_symlink(self):
  f=self.root/'link';f.symlink_to(self.file)
  with self.assertRaises(ValueError):d.regular(f)
 def test_actual_output_bytes(self):
  expected={'test.py':{'bytes':self.file.stat().st_size,'sha256':d.digest(self.file)}}
  self.assertEqual(d.validate_artifacts(self.root/'source',expected),expected)
  self.file.write_text('example=2\n')
  with self.assertRaises(ValueError):d.validate_artifacts(self.root/'source',expected)
 def test_extra_output(self):
  with self.assertRaises(ValueError):d.validate_artifacts(self.root/'source',{})
 def test_output_link(self):
  (self.root/'source/link').symlink_to(self.file)
  with self.assertRaises(ValueError):d.validate_artifacts(self.root/'source',{})
 def test_schema(self):
  self.lock['schema']='other';self.pin=self.write_lock()
  with self.assertRaises(ValueError):d.source_check(self.pin)
if __name__=='__main__':unittest.main()
