import ast,hashlib,json,pathlib,unittest,tempfile,os,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import derive
ROOT=pathlib.Path(__file__).resolve().parent
class Tests(unittest.TestCase):
 def test_exact_two_original_changes(self):
  b=(ROOT/'sentinel.py').read_bytes();old=b.replace(b'UPSTREAM_TOTAL_TIMEOUT_S = 210 ',b'UPSTREAM_TOTAL_TIMEOUT_S = 40 ').replace(b'MAX_REQUEST_SECONDS = 220 ',b'MAX_REQUEST_SECONDS = 50 ')
  self.assertEqual(hashlib.sha256(old).hexdigest(),'4cbd5f439cca3f899533e4c2e8ac1674c798a69b4b9a881eaa2f11234b0bc06b')
 def test_retained_limits(self):
  tree=ast.parse((ROOT/'sentinel.py').read_bytes());v={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in ('UPSTREAM_TOTAL_TIMEOUT_S','MAX_REQUEST_SECONDS','UPSTREAM_CONNECT_TIMEOUT_S','MAX_CONCURRENT_REQUESTS')};self.assertEqual(v,{'UPSTREAM_TOTAL_TIMEOUT_S':210,'MAX_REQUEST_SECONDS':220,'UPSTREAM_CONNECT_TIMEOUT_S':10,'MAX_CONCURRENT_REQUESTS':16})
 def test_build_does_not_replace_application(self):
  s=(ROOT/'derive-in-container.sh').read_text();self.assertEqual(s.count('install -m0644 /w/sentinel.py'),1);self.assertNotIn('public_inputs.py',s);self.assertNotIn('lifecycle.py',s);self.assertIn('sentinel inventory row mismatch',s)
class InputControls(unittest.TestCase):
 def test_regular_pin_and_mutation(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d);(p/'file').write_bytes(b'a');row={'file':{'bytes':1,'sha256':hashlib.sha256(b'a').hexdigest()}};derive.pins(p,row);(p/'file').write_bytes(b'b')
   with self.assertRaises(ValueError):derive.pins(p,row)
 def test_linked_input_refused(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d);(p/'source').write_bytes(b'a');(p/'sym').symlink_to(p/'source');os.link(p/'source',p/'hard');row={'bytes':1,'sha256':hashlib.sha256(b'a').hexdigest()}
   for name in ('sym','hard'):
    with self.assertRaises(ValueError):derive.pins(p,{name:row})
if __name__=='__main__':unittest.main()
