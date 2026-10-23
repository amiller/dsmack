"""Host-only original grammar controls. No provider/model/candidate execution."""
import hashlib,json,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import acceptance_inputs as a
class Tests(unittest.TestCase):
 def setUp(self):
  self.raw=(pathlib.Path(__file__).parent/'fixtures/suite-wire/actual-gen1-42ce.json').read_bytes()
 def test_actual_authenticated_suite_boolean_bytes_unchanged(self):
  self.assertEqual(hashlib.sha256(self.raw).hexdigest(),'42ce2f6608eb3ffe1c99e34fd8664b3ca44a5cdfeabae1283697e0bce805db3e')
  self.assertIs(json.loads(self.raw)['tests'][8]['steps'][3]['value'],True)
  self.assertEqual(a.admit_suite_bytes(self.raw),self.raw)
 def test_s0_scalar_grammar_remains_strict(self):
  with self.assertRaises(ValueError):a.p.parse_json(b'{"value":true}')
 def test_duplicate_nonfinite_unknown_and_noncanonical_refuse(self):
  value=json.loads(self.raw);value['unexpected']=True
  unknown=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
  bad=[b'{"schema":"dsmack-bounty-browser-suite/1",'+self.raw[1:],self.raw.replace(b'"value":true',b'"value":NaN'),self.raw.replace(b'"value":true',b'"value":1.0'),unknown,self.raw+b'\n',b'{}',b'x'*262145]
  for raw in bad:
   with self.subTest(size=len(raw)):
    with self.assertRaises(ValueError):a.admit_suite_bytes(raw)
if __name__=='__main__':unittest.main()
