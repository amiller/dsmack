"""Detect timestamp-valid cache substitution without changing selected sources."""
import importlib.util,os,py_compile,shutil,tempfile,unittest
from pathlib import Path

class SourceLoading(unittest.TestCase):
 def test_matching_cache_cannot_replace_selected_module(self):
  here=Path(__file__).resolve().parent
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);shutil.copy2(here/'coordinator.py',root/'coordinator.py');shutil.copytree(here/'modulepack',root/'modulepack')
   target=root/'modulepack/approved_run.py';original=target.read_bytes();st=target.stat();marker=root/'CACHE-EXECUTED'
   malicious=("from pathlib import Path;Path("+repr(str(marker))+").touch()\n").encode()
   self.assertLess(len(malicious),len(original));malicious+=b' '*(len(original)-len(malicious))
   target.write_bytes(malicious);os.utime(target,ns=(st.st_atime_ns,st.st_mtime_ns));py_compile.compile(str(target),doraise=True)
   target.write_bytes(original);os.utime(target,ns=(st.st_atime_ns,st.st_mtime_ns))
   # The cache really matches timestamp and size: standard loading runs marker.
   sp=importlib.util.spec_from_file_location('cache_control',target);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
   self.assertTrue(marker.exists());marker.unlink()
   sp=importlib.util.spec_from_file_location('selected_coordinator',root/'coordinator.py');c=importlib.util.module_from_spec(sp);sp.loader.exec_module(c)
   selected=c.modules();self.assertEqual(set(selected),set(c.MODULES));self.assertFalse(marker.exists())
if __name__=='__main__':unittest.main()
