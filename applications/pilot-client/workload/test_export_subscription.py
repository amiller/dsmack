import json,pathlib,subprocess,sys,tempfile,time,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import export_subscription as e
class Tests(unittest.TestCase):
 def setUp(self):self.v=e.validator();self.inner={'accessToken':'DUMMY-NOT-A-TOKEN','refreshToken':'DUMMY-NOT-A-REFRESH','expiresAt':int((time.time()+7200)*1000),'scopes':['user:inference']};self.doc={'claudeAiOauth':dict(self.inner,extraIgnoredMetadata={'model':'not exported'}),'unrelatedClientEntry':'not exported'}
 def test_fixed_auth_fields_only_original_validator_accepts(self):
  raw=e.project(json.dumps(self.doc).encode(),self.v,time.time());self.assertEqual(json.loads(raw),{'claudeAiOauth':self.inner});self.v.parse_subscription_document(raw)
 def test_inference_only_has_no_lifetime_check(self):
  oauth={'accessToken':'sk-ant-oat01-DUMMY','scopes':['user:inference']}
  for raw in (b'sk-ant-oat01-DUMMY\n',json.dumps({'claudeAiOauth':oauth}).encode()):
   exported=e.project(raw,self.v,4102444800);self.assertEqual(json.loads(exported),{'claudeAiOauth':oauth})
 def test_missing_required_or_short_lifetime_refuses(self):
  for inner in ({'refreshToken':'dummy'},dict(self.inner,expiresAt=1000)):
   with self.assertRaises(ValueError):e.project(json.dumps({'claudeAiOauth':inner}).encode(),self.v,time.time())
 def test_duplicate_whole_store_refuses(self):
  with self.assertRaises(ValueError):e.project(b'{"claudeAiOauth":{},"claudeAiOauth":{}}',self.v,time.time())
 def test_invalid_known_auth_field_not_filtered_away(self):
  with self.assertRaises(ValueError):e.project(json.dumps({'claudeAiOauth':dict(self.inner,scopes=['invalid scope'])}).encode(),self.v,time.time())
 def test_cli_requires_explicit_flag_and_regular600_source(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d)/'source';p.write_text(json.dumps(self.doc));p.chmod(0o600)
   base=[sys.executable,'-I',str(pathlib.Path(e.__file__)),'--source',str(p)]
   r=subprocess.run(base,capture_output=True);self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'')
   r=subprocess.run(base+['--emit-credential-stdout'],capture_output=True);self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout),{'claudeAiOauth':self.inner});self.assertEqual(r.stderr,b'')
   p.chmod(0o644);r=subprocess.run(base+['--emit-credential-stdout'],capture_output=True);self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'')
 def test_argument_failure_value_free(self):
  r=subprocess.run([sys.executable,'-I',e.__file__,'--unknown-DUMMYSECRET'],capture_output=True);self.assertEqual(r.returncode,2);self.assertNotIn(b'DUMMYSECRET',r.stderr)
if __name__=='__main__':unittest.main()
