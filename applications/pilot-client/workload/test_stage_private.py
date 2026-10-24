import importlib.util,json,os,pathlib,subprocess,sys,tempfile,types,unittest
from unittest import mock
P=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('stage_private',P/'stage_private.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
v=types.ModuleType('validator');exec(compile(s.raw(P/'reference/claude_subscription_document.py'),'validator','exec'),v.__dict__)
class Tests(unittest.TestCase):
 def doc(self):return {'claudeAiOauth':{'accessToken':'DUMMY-ACCESS','refreshToken':'DUMMY-REFRESH','expiresAt':4000000,'scopes':['user:inference']}}
 def test_fresh(self):value,expiry=s.credential(json.dumps(self.doc()).encode(),1000,v);self.assertEqual(expiry,4000);self.assertEqual(json.loads(value),self.doc())
 def test_ttl(self):
  for now in (2801,4000,5000):
   with self.assertRaises(ValueError):s.credential(json.dumps(self.doc()).encode(),now,v)
 def test_injection(self):
  for field in ('settings','hooks','mcpServers','env','model','provider_route'):
   d=self.doc();d[field]={}
   with self.assertRaises(ValueError):s.credential(json.dumps(d).encode(),1000,v)
   d=self.doc();d['claudeAiOauth'][field]='dummy'
   with self.assertRaises(ValueError):s.credential(json.dumps(d).encode(),1000,v)
 def test_duplicates(self):
  with self.assertRaises(ValueError):s.credential(b'{"claudeAiOauth":{},"claudeAiOauth":{}}',1000,v)
 def test_missing_or_wrong_type(self):
  for field,value in [('refreshToken',None),('expiresAt',True),('accessToken','')]:
   d=self.doc();d['claudeAiOauth'][field]=value
   with self.assertRaises(ValueError):s.credential(json.dumps(d).encode(),1000,v)
 def test_value_free_cli_argument_refusal(self):
  marker='DUMMY-ARGUMENT-MUST-NOT-BE-ECHOED'
  r=subprocess.run([sys.executable,'-I','-B',str(P/'stage_private.py'),'--unexpected',marker],input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/tmp','TMPDIR':'/tmp'})
  self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'');self.assertEqual(r.stderr,b'DSMACK_PRIVATE_STAGE_REFUSED ValueError\n');self.assertNotIn(marker.encode(),r.stdout+r.stderr)
 def test_linux_backend_remains_explicit(self):
  a=types.SimpleNamespace(transport_backend='linux-memfd-v1',portable_module=None,temporary_parent=None,transport_module='selected')
  with mock.patch.object(s.sys,'platform','linux'),mock.patch.object(s.os,'memfd_create',create=True),mock.patch.object(s,'load',return_value='original')as loader:
   self.assertEqual(s.selected_transport(a),'original');loader.assert_called_once_with('selected')
  a.portable_module='extra'
  with self.assertRaises(ValueError):s.selected_transport(a)
 def test_no_platform_fallback(self):
  a=types.SimpleNamespace(transport_backend='linux-memfd-v1',portable_module=None,temporary_parent=None,transport_module='selected')
  with mock.patch.object(s.sys,'platform','darwin'),mock.patch.object(s,'load')as loader:
   with self.assertRaises(ValueError):s.selected_transport(a)
   loader.assert_not_called()
 def test_portable_module_required(self):
  a=types.SimpleNamespace(transport_backend='darwin-owned-tempfile-v1',portable_module=None,temporary_parent=None,transport_module='selected')
  with mock.patch.object(s.sys,'platform','darwin'):
   with self.assertRaises(ValueError):s.selected_transport(a)
 def test_input_deadline(self):
  r,w=os.pipe()
  try:
   with os.fdopen(r,'rb')as stream:
    with self.assertRaises(TimeoutError):s.bounded_stdin(stream,0.02)
  finally:os.close(w)
 def test_parent_permissions(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d);p.chmod(0o700);s.private_parent(p);p.chmod(0o755)
   with self.assertRaises(ValueError):s.private_parent(p)
 def test_exclusive_write_no_symlinks(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d)/'file';s.write(p,b'dummy');self.assertEqual(p.stat().st_mode&0o777,0o600)
   with self.assertRaises(OSError):s.write(p,b'other')
   link=pathlib.Path(d)/'link';link.symlink_to(pathlib.Path(d)/'absent')
   with self.assertRaises(OSError):s.write(link,b'dummy')
if __name__=='__main__':unittest.main()
