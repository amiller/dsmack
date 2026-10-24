import json,pathlib,tempfile,unittest
from unittest.mock import patch
import models_health as h
class V:
 def parse_subscription_document(self,b):return {'accessToken':'DUMMY-PRIVATE','expiresAt':4102444800000}
class Connection:
 status=200;calls=[];closed=False
 def __init__(self,host,**kwargs):assert host=='api.anthropic.com'
 def request(self,method,path,headers):self.__class__.calls.append((method,path));assert headers['Authorization']=='Bearer DUMMY-PRIVATE'
 def getresponse(self):return self
 def read(self,n):return b'PRIVATE RESPONSE NEVER EXPORT'
 def close(self):self.__class__.closed=True
class Tests(unittest.TestCase):
 def test_closed_status_classification_no_body(self):
  for status,category in [(200,'models_route_ok'),(401,'authentication_refused'),(403,'permission_refused'),(302,'redirect_refused'),(429,'rate_limited'),(503,'provider_server_error')]:
   Connection.status=status
   with patch.multiple(h,protected=lambda _:None,regular=lambda *_:b'dummy',load_validator=lambda _:V()),patch.object(h.ssl,'create_default_context',return_value=None):v=h.health('/private/doc','unused',connection=Connection)
   self.assertEqual(v['category'],category);self.assertNotIn('PRIVATE',json.dumps(v));self.assertFalse(v['refresh_performed']);self.assertTrue(Connection.closed)
  self.assertTrue(all(x==('GET','/v1/models')for x in Connection.calls))
 def test_transport_error_redacted(self):
  class Fail(Connection):
   def request(self,*a,**kw):raise OSError('DUMMY-PRIVATE')
  with patch.multiple(h,protected=lambda _:None,regular=lambda *_:b'dummy',load_validator=lambda _:V()),patch.object(h.ssl,'create_default_context',return_value=None):v=h.health('/private/doc','unused',connection=Fail)
  self.assertEqual(v['category'],'transport_error');self.assertNotIn('PRIVATE',json.dumps(v))
if __name__=='__main__':unittest.main()
