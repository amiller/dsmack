import base64,hashlib,json,os,tempfile,unittest
from pathlib import Path
P=Path(__file__).parent
scope={'__name__':'portable_test','__file__':str(P/'portable.py')};exec(compile((P/'portable.py').read_bytes(),str(P/'portable.py'),'exec'),scope)
client={'__name__':'client_test','__file__':str(P/'client.py')};exec(compile((P/'client.py').read_bytes(),str(P/'client.py'),'exec'),client)
setup={'__name__':'setup_test','__file__':str(P/'setup.py')};exec(compile((P/'setup.py').read_bytes(),str(P/'setup.py'),'exec'),setup)
worker={'__name__':'worker_test','__file__':str(P/'worker.py')};exec(compile((P/'worker.py').read_bytes(),str(P/'worker.py'),'exec'),worker)
class Portable(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='.arcade-test-',dir=Path.home());self.root=Path(self.tmp.name);self.root.chmod(0o700)
 def tearDown(self):self.tmp.cleanup()
 def test_setup_default_mac_path_and_early_long_path_refusal(self):
  state=setup['state_directory'](Path('/Users/amiller/.dsmack-arcade'))
  self.assertEqual(state,Path('/Users/amiller/.dsmack-arcade/s'))
  with self.assertRaisesRegex(ValueError,'shorter owned state_dir'):
   setup['state_directory'](Path('/Users/a-much-longer-account-name/.dsmack-arcade'))
  chosen=Path.home()/('as-'+self.root.name[-4:])
  short=setup['state_directory'](self.root/'installation',str(chosen))
  self.assertEqual(short,chosen)
  # main must refuse before reading the absent key or reaching the API/download.
  import sys
  old=sys.argv
  try:
   sys.argv=['setup.py','--api','https://never-contact.example','--home',str(self.root/('x'*100)),'--node','/missing-node','--public-key','/missing-key']
   with self.assertRaisesRegex(ValueError,'shorter owned state_dir'):setup['main']()
  finally:sys.argv=old
 def test_duplicate_document_refused(self):
  with self.assertRaises(ValueError):scope['document'](b'{"a":1,"a":2}')
 def test_symlink_and_world_write_refused(self):
  p=self.root/'file';p.write_bytes(b'x');p.chmod(0o600);(self.root/'link').symlink_to(p)
  with self.assertRaises(ValueError):scope['read'](self.root/'link')
  p.chmod(0o666)
  with self.assertRaises(ValueError):scope['read'](p)
 def test_http_and_userinfo_refused(self):
  for url in ('http://example.com','https://user:password@example.com','https://example.com/bad/../path'):
   with self.assertRaises(ValueError):client['API'](url)
  client['API']('http://127.0.0.1:8788',True)
  self.assertEqual(client['API']('https://example.com/arcade-pilot').prefix,'/arcade-pilot')
 def test_cross_origin_download_refused_before_file(self):
  api=client['API']('https://example.com')
  with self.assertRaises(ValueError):api.fetch({'url':'https://other.example/file'},self.root/'x')
  self.assertFalse((self.root/'x').exists())
 def test_bounded_download_and_final_hash(self):
  import io
  payload=b'x'*(4194304+7);calls=[]
  class Response:
   status=206
   def __init__(self,start,end):self.start=start;self.end=end
   def getheader(self,name):return {'Content-Length':str(self.end-self.start+1)}.get(name)
   def read(self,limit):return payload[self.start:self.end+1]
  class Connection:
   def __init__(self,*a,**k):pass
   def request(self,method,path,headers):
    span=headers['Range'].split('=')[1];self.start,self.end=map(int,span.split('-'));calls.append((self.start,self.end))
   def getresponse(self):return Response(self.start,self.end)
   def close(self):pass
  old=client['http'].client.HTTPSConnection;client['http'].client.HTTPSConnection=Connection
  try:
   d={'url':'https://example.com/arcade-pilot/api/artifacts/a/workload.img','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
   client['API']('https://example.com/arcade-pilot').fetch(d,self.root/'download')
   self.assertEqual(calls,[(0,4194303),(4194304,4194310)]);self.assertEqual((self.root/'download').read_bytes(),payload)
   with self.assertRaisesRegex(ValueError,'digest mismatch'):client['API']('https://example.com/arcade-pilot').fetch({**d,'sha256':'0'*64},self.root/'bad')
   partial=self.root/'partial';partial.write_bytes(payload[:4194304]);partial.chmod(0o600)
   api=client['API']('https://example.com/arcade-pilot')
   with self.assertRaisesRegex(ValueError,'explicit reconciliation'):api.fetch(d,partial)
   api.resume_download=True;calls.clear();api.fetch(d,partial)
   self.assertEqual(calls,[(4194304,4194310)]);self.assertEqual(partial.read_bytes(),payload)
   bad=self.root/'bad-prefix';bad.write_bytes(b'bad');bad.chmod(0o600)
   with self.assertRaisesRegex(ValueError,'digest mismatch'):api.fetch(d,bad)
   Response.status=200
   with self.assertRaisesRegex(ValueError,'bounded artifact response'):client['API']('https://example.com/arcade-pilot').fetch(d,self.root/'unbounded')
  finally:client['http'].client.HTTPSConnection=old
 def test_original_membership_and_caps(self):
  for name in scope['ORIGINALS']:(self.root/name).write_bytes(b'x');(self.root/name).chmod(0o600)
  rows=scope['evidence_manifest'](self.root);self.assertEqual(len(rows),21)
  (self.root/'statement.json').unlink();(self.root/'statement.json').symlink_to(self.root/'envelope.json')
  with self.assertRaises(ValueError):scope['evidence_manifest'](self.root)
 def test_authority_window_covers_transport_and_commit(self):
  import datetime
  a={'__name__':'authority_test','__file__':str(P/'authority.py')};exec(compile((P/'authority.py').read_bytes(),str(P/'authority.py'),'exec'),a)
  now=datetime.datetime(2026,10,23,tzinfo=datetime.timezone.utc)
  self.assertEqual((a['admission_expiry'](now,now+datetime.timedelta(hours=3))-now).total_seconds(),7200)
  self.assertEqual((a['admission_expiry'](now,now+datetime.timedelta(seconds=4000))-now).total_seconds(),4000)
  with self.assertRaisesRegex(ValueError,'close to expiry'):a['admission_expiry'](now,now+datetime.timedelta(seconds=3599))
 def test_native_socket_path_budget(self):
  p=scope['task_directory']('/Users/amiller/ap','a'*32)
  self.assertLess(len(str(p/('attempt-'+('b'*32)+'.helper/net.sock')).encode()),104)
  with self.assertRaisesRegex(ValueError,'shorter owned state_dir'):scope['task_directory']('/Users/amiller/a-very-long-runtime-namespace/state','a'*32)
 def test_plan_binding_before_subprocess(self):
  old=scope['release'];scope['release']=lambda c:None
  try:
   native='a'*32;run=self.root/'run';run.mkdir(mode=0o700);control=run/('attempt-'+native+'.control');control.mkdir(mode=0o700)
   cfg={'install_root':str(self.root),'profile_id':'pilot'}
   for n in ('bootstrap','inventory','signature'):
    p=self.root/n;p.write_bytes(b'{}');p.chmod(0o600);cfg[n]=str(p)
   task=self.root/'task';task.write_bytes(b'{}');task.chmod(0o600);(control/'plan.json').write_bytes(b'{"schema":"different-valid-plan"}');(control/'plan.json').chmod(0o600)
   with self.assertRaisesRegex(ValueError,'saved plan'):scope['coordinator'](cfg,'run',task,run,native)
  finally:scope['release']=old
 def test_upload_resumes_after_persisted_chunk_offset(self):
  for name in scope['ORIGINALS']:
   path=self.root/name;path.write_bytes(b'x');path.chmod(0o600)
  names=list(scope['ORIGINALS']);calls=[]
  class API:
   def request(self,method,path,body=None,*args):
    calls.append((method,path,body))
    if method=='GET':return {'state':'prepared'}
    if method=='POST'and path.endswith('/evidence'):return {'submission_id':'d'*32,'chunk_bytes':4194304,'files':[{'name':n,'received':1 if n==names[0]else 0}for n in names]}
    return {}
  client['upload'](API(),'a'*32,'b'*43,self.root,'request-id-0000001')
  puts=[x for x in calls if x[0]=='PUT'];self.assertEqual(len(puts),20);self.assertFalse(any(x[1].endswith('/'+names[0])for x in puts))
 def test_uncertain_job_does_not_execute_handler(self):
  key=self.root/'token';key.write_text('a'*43);key.chmod(0o600)
  lease={'job_id':'b'*32,'lease_id':'c'*32,'lease_expires_at':2000000000,'action':'registration','input':{},'input_sha256':hashlib.sha256(b'{}').hexdigest()}
  d=self.root/lease['job_id'];d.mkdir(mode=0o700);(d/'intent.json').write_bytes(b'{}')
  class API:
   def __init__(self):self.posts=[]
   def request(self,method,path,body,token):
    self.posts.append((path,body));return lease if path.endswith('/lease') else {}
  api=API();worker['run_one']({'credential_file':str(key),'state_dir':str(self.root),'worker_id':'one','handlers':{'registration':{'path':'MUST_NOT_EXECUTE'}},'timeout_seconds':120},api)
  self.assertEqual(api.posts[-1][1]['status'],'uncertain');self.assertFalse(api.posts[-1][1]['result']['automatic_retry'])
class Factory(unittest.TestCase):
 def setUp(self):
  self.f={'__name__':'factory_test','__file__':str(P/'task_factory.py')};exec(compile((P/'task_factory.py').read_bytes(),str(P/'task_factory.py'),'exec'),self.f)
 def test_projection_ignores_candidate_test_and_package_changes(self):
  base={n:b'original'for n in self.f['ALLOWED']};base.update({'package.json':b'trusted','test.js':b'trusted-test'})
  submitted={n:b'new-ui'for n in self.f['ALLOWED']};submitted.update({'package.json':b'process.exit(0)','test.js':b'fake-pass','extra.txt':b'unexecuted'})
  candidate=self.f['project_candidate'](base,submitted)
  self.assertEqual(candidate['package.json'],b'trusted');self.assertEqual(candidate['test.js'],b'trusted-test');self.assertNotIn('extra.txt',candidate)
  self.assertEqual(set(candidate),set(base))
 def test_missing_candidate_file_refuses(self):
  with self.assertRaises(ValueError):self.f['project_candidate']({}, {'apps/board/logic.js':b'partial'})
 def test_manifest_has_no_candidate_command_or_private_channel(self):
  old=self.f['selected'];self.f['selected']=lambda d: b'{"network":{"mode":"none"},"harness":{"name":"python-application","path":"/usr/bin/python3","sha256":"held"}}'
  try:
   m=self.f['manifest']({'reference_manifest':{}});compose=json.loads(m['docker_compose_file']);service=compose['services']['checker']
   self.assertEqual(service['entrypoint'],['/usr/bin/python3','-I','-B']);self.assertEqual(service['command'],['/workspace/inputs/driver.py']);self.assertFalse(m['allowed_envs']);self.assertNotIn('credentials',m)
   self.assertEqual(len(m['outputs']['artifacts']),8);self.assertTrue(all(x['mode']=='ro'for x in m['allowed_files']))
  finally:self.f['selected']=old
if __name__=='__main__':unittest.main()
