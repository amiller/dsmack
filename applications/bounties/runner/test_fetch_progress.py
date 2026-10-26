import contextlib,hashlib,io,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
P=Path(__file__).parent
client={'__name__':'client_test','__file__':str(P/'client.py')};exec(compile((P/'client.py').read_bytes(),str(P/'client.py'),'exec'),client)
CAP='S'*43;PAYLOAD=bytes(range(256))*(9*4096+1)
class Response:
 status=206
 def __init__(self,start,end):self.start,self.end=start,end
 def getheader(self,name):return {'Content-Length':str(self.end-self.start+1)}.get(name)
 def read(self,limit):return PAYLOAD[self.start:self.end+1]
class Connection:
 def __init__(self,*a,**k):pass
 def request(self,method,path,body=None,headers=None):assert headers['Authorization']=='Bearer '+CAP;self.start,self.end=map(int,headers['Range'].split('=')[1].split('-'))
 def getresponse(self):return Response(self.start,self.end)
 def close(self):pass
D={'url':'https://example.com/arcade-pilot/api/artifacts/secret-job/workload.img','bytes':len(PAYLOAD),'sha256':hashlib.sha256(PAYLOAD).hexdigest()}
class FetchProgress(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(prefix='.fetch-',dir=Path.home());self.addCleanup(t.cleanup);self.root=Path(t.name);self.root.chmod(0o700)
  for p in (patch.object(client['http'].client,'HTTPSConnection',Connection),patch.dict(client,{'PROGRESS_BYTES':1<<20})):p.start();self.addCleanup(p.stop)
 def fetch(self,d,path,resume=False):
  api=client['API']('https://example.com/arcade-pilot');api.resume_download=resume;err=io.StringIO()
  with contextlib.redirect_stderr(err):
   try:api.fetch(d,path,CAP)
   finally:self.out=err.getvalue()
  return self.out
 def assertPublic(self,out):
  for secret in (CAP,'example.com','secret-job',str(self.root)):self.assertNotIn(secret,out)
 def test_large_fetch_reports_bytes_then_verified_without_secrets(self):
  out=self.fetch(D,self.root/'workload.img');lines=out.splitlines()
  self.assertTrue(all(x.startswith('workload.img: ')for x in lines));self.assertIn(f'4194304/{len(PAYLOAD)} bytes (',out)
  self.assertEqual(lines[-1],f'workload.img: VERIFIED {len(PAYLOAD)} bytes, sha256 matches');self.assertPublic(out)
 def test_resume_reports_rehashed_offset(self):
  partial=self.root/'workload.img';partial.write_bytes(PAYLOAD[:4<<20]);partial.chmod(0o600)
  out=self.fetch(D,partial,True);self.assertTrue(out.startswith(f'workload.img: resuming at {4<<20}/{len(PAYLOAD)} bytes (44%) after rehashing'));self.assertIn('VERIFIED',out)
  self.assertEqual(partial.read_bytes(),PAYLOAD);self.assertPublic(out)
 def test_bad_hash_never_reports_verified(self):
  with self.assertRaisesRegex(ValueError,'digest mismatch'):self.fetch({**D,'sha256':'0'*64},self.root/'bad.img')
  self.assertIn('bytes (',self.out);self.assertNotIn('VERIFIED',self.out);self.assertPublic(self.out)
 def test_small_fetch_stays_silent(self):
  small=PAYLOAD[:1<<20]
  with patch.dict(globals(),{'PAYLOAD':small}):self.assertEqual(self.fetch({**D,'bytes':len(small),'sha256':hashlib.sha256(small).hexdigest()},self.root/'small'),'')
if __name__=='__main__':unittest.main()
