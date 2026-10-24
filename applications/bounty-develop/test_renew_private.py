import pathlib,tempfile,time,unittest
from unittest.mock import patch
import renew_private as r
class Validator:
 def parse_subscription_document(self,b):
  import json
  return json.loads(b)['claudeAiOauth']
 def canonical_env_value(self,v):
  import json
  return json.dumps({'claudeAiOauth':v})
class Refresh:
 calls=0
 def __init__(self,v,url,ca):
  if url!='https://api.anthropic.com':raise ValueError()
  self._oauth=v
 def refresh(self):self.__class__.calls+=1;self._oauth={'expiresAt':int((time.time()+3600)*1000),'accessToken':'dummy','refreshToken':'dummy'}
class Tests(unittest.TestCase):
 def run_fixture(self,cls=Refresh):
  d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup);root=pathlib.Path(d.name);src=root/'source';src.write_bytes(b'{"claudeAiOauth":{"expiresAt":1}}');src.chmod(0o600);out=root/'out';out.mkdir(mode=0o700)
  return root,src,out,patch.multiple(r,load_refresh=lambda _:cls,load_validator=lambda _:Validator(),protected=lambda _:None)
 def test_success_no_private_digest(self):
  _,src,out,p=self.run_fixture()
  with p:v=r.renew(src,out,'unused','unused','unused')
  self.assertTrue(v['complete']);self.assertFalse(v['private_content_hashed']);self.assertEqual((out/'credential.json').stat().st_mode&0o777,0o600)
 def test_failure_intent_prevents_retry(self):
  class Fail(Refresh):
   def refresh(self):raise RuntimeError('dummy secret response')
  _,src,out,p=self.run_fixture(Fail)
  with p:
   with self.assertRaises(RuntimeError):r.renew(src,out,'unused','unused','unused')
   self.assertTrue((out/'REFRESH-STARTED.json').exists());self.assertFalse((out/'credential.json').exists())
   with self.assertRaises(ValueError):r.renew(src,out,'unused','unused','unused')
 def test_short_ttl_refuses(self):
  class Short(Refresh):
   def refresh(self):self._oauth={'expiresAt':int((time.time()+1199)*1000)}
  _,src,out,p=self.run_fixture(Short)
  with p:
   with self.assertRaises(ValueError):r.renew(src,out,'unused','unused','unused')
  self.assertTrue((out/'credential.json').exists());self.assertTrue((out/'REFRESH-LAUNCH-INADMISSIBLE.json').exists())
 def test_links_and_source_pin_refuse(self):
  root,src,out,p=self.run_fixture();link=root/'link';link.symlink_to(src)
  with self.assertRaises(OSError):r.regular(link,65536,True)
  with self.assertRaises(ValueError):r.load_refresh(src)
if __name__=='__main__':unittest.main()
