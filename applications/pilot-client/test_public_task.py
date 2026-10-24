import hashlib,io,tarfile,tempfile,unittest
from pathlib import Path
import public_task as p
S='bounty-board-search-browser-review-v1'
class Payload(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=Path.home());self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.context=p.canonical({'schema':'dsmack-result-closure-context/1','attempt_id':'1'*32,'selectors':[S]});self.msha=hashlib.sha256(b'{}').hexdigest()
 def tearDown(self):self.tmp.cleanup()
 def archive(self,omit=False,extra=None):
  files={p.CONTEXT:self.context,'manifests/'+S+'.app-compose.json':b'{}','WORKLOAD':(S+'\n').encode(),'data':b'hello'}
  if extra:files.update(extra)
  files['SHA256SUMS']=b'' if omit else ''.join(hashlib.sha256(v).hexdigest()+'  '+k+'\n' for k,v in files.items()).encode()
  b=io.BytesIO()
  with tarfile.open(fileobj=b,mode='w',format=tarfile.USTAR_FORMAT) as t:
   for k,v in files.items():
    m=tarfile.TarInfo(k);m.mode=0o600;m.mtime=1784592000;m.size=len(v);t.addfile(m,io.BytesIO(v))
  raw=b.getvalue();return raw+b'\0'*((-len(raw))%1048576)
 def save(self,b,name='disk'):
  path=self.root/name;path.write_bytes(b);path.chmod(0o600);return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 def test_positive_and_reprepare(self):
  seed=self.save(self.archive());self.assertEqual(p.scan_payload(seed,S,self.msha,self.context)['closure_raw'],self.context)
  new=self.context.replace(b'1'*32,b'2'*32);out=self.root/'new';self.assertEqual(p.prepare_payload(seed,new,S,self.msha,out)['closure_raw'],new)
  with tarfile.open(out) as archive:self.assertTrue(all(m.mtime==1784592000 for m in archive))
  with tarfile.open(seed['path']) as before,tarfile.open(out) as after:
   a=before.extractfile('SHA256SUMS').read().splitlines();b=after.extractfile('SHA256SUMS').read().splitlines();self.assertEqual([r[64:] for r in a],[r[64:] for r in b])
 def test_old_disk_new_context_refuses(self):
  with self.assertRaisesRegex(ValueError,'packaged closure'):p.scan_payload(self.save(self.archive()),S,self.msha,self.context.replace(b'1'*32,b'2'*32))
 def test_checksum_omission(self):
  with self.assertRaisesRegex(ValueError,'membership'):p.scan_payload(self.save(self.archive(True)),S,self.msha)
 def test_padding(self):
  for i,raw in enumerate([self.archive()+b'\0'*1048576,self.archive()[:-1]+b'x',self.archive()[:1024]]):
   with self.subTest(i=i),self.assertRaises(ValueError):p.scan_payload(self.save(raw,str(i)),S,self.msha)
 def test_duplicate(self):
  raw=self.archive();size=int(raw[124:136].strip(b'\0 '),8);end=512+((size+511)//512)*512;duplicate=raw[:end]+raw;duplicate+=b'\0'*((-len(duplicate))%1048576)
  with self.assertRaisesRegex(ValueError,'duplicate'):p.scan_payload(self.save(duplicate),S,self.msha)
 def test_unsupported_headers_and_aliases(self):
  for i,kind in enumerate(('pax','link','fifo','sparse','alias','ancestor','nonzero-pad','truncated-end')):
   raw=self.archive()
   if kind in ('pax','link','fifo','sparse'):
    h=tarfile.TarInfo('extra');h.type={'pax':tarfile.XHDTYPE,'link':tarfile.SYMTYPE,'fifo':tarfile.FIFOTYPE,'sparse':tarfile.GNUTYPE_SPARSE}[kind];raw=h.tobuf(tarfile.USTAR_FORMAT)+raw
   elif kind in ('alias','ancestor'):
    h=tarfile.TarInfo('Closure-context/other' if kind=='alias' else 'closure-context');h.mode=0o600;raw=h.tobuf(tarfile.USTAR_FORMAT)+raw
   elif kind=='nonzero-pad':
    size=int(raw[124:136].strip(b'\0 '),8);raw=raw[:512+size]+b'x'+raw[513+size:]
   else:raw=raw[:512]
   raw+=b'\0'*((-len(raw))%1048576)
   with self.subTest(kind=kind),self.assertRaises(ValueError):p.scan_payload(self.save(raw,'bad'+str(i)),S,self.msha)
 def test_changed_bytes_refused_again(self):
  disk=self.save(self.archive());p.scan_payload(disk,S,self.msha,self.context)
  Path(disk['path']).write_bytes(self.archive(True))
  with self.assertRaises(ValueError):p.scan_payload(disk,S,self.msha,self.context)
 def test_symlink(self):
  target=self.save(self.archive());link=self.root/'link';link.symlink_to(target['path'])
  with self.assertRaises(ValueError):p.scan_payload(dict(target,path=str(link)),S,self.msha)
 def test_generate_refuses_actual_competing_public_channel(self):
  global S
  previous=S;S='bounty-board-search-generate-v1';self.context=p.canonical({'schema':'dsmack-result-closure-context/1','attempt_id':'1'*32,'selectors':[S]})
  try:
   self.assertEqual(p.scan_payload(self.save(self.archive(),'generate-positive'),S,self.msha)['closure_context']['selectors'],[S])
   with self.assertRaisesRegex(ValueError,'public runtime channel'):p.scan_payload(self.save(self.archive(extra={'public-inputs/request.json':b'synthetic'}),'generate-bad'),S,self.msha)
  finally:S=previous
 def test_develop_refuses_competing_actual_public_archive_channels(self):
  global S
  previous=S;S='bounty-board-search-develop-v1';self.context=p.canonical({'schema':'dsmack-result-closure-context/1','attempt_id':'1'*32,'selectors':[S]})
  try:
   self.assertEqual(p.scan_payload(self.save(self.archive(),'positive'),S,self.msha)['closure_context']['selectors'],[S])
   for i,name in enumerate(('public-inputs/request.json','envelopes/develop.envelope.json','broker/credential.json')):
    with self.assertRaisesRegex(ValueError,'public runtime channel'):p.scan_payload(self.save(self.archive(extra={name:b'synthetic'}),'bad'+str(i)),S,self.msha)
  finally:S=previous
if __name__=='__main__':unittest.main()
