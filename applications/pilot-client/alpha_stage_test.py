import hashlib,io,json,os,shutil,tarfile,tempfile,unittest,subprocess
from pathlib import Path
from alpha_stage import stage,authenticate

def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
class Stage(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.runtime=tempfile.TemporaryDirectory(prefix='.dsmack-alpha-node-test-',dir=Path.home());cls.selected_node=Path(cls.runtime.name)/'node'
  shutil.copyfile(Path(shutil.which('node')).resolve(),cls.selected_node);os.chmod(cls.selected_node,0o700)
 @classmethod
 def tearDownClass(cls):cls.runtime.cleanup()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='.dsmack-alpha-stage-test-',dir=Path.home());self.root=Path(self.temp.name);self.src=self.root/'bootstrap';self.src.mkdir(mode=0o700)
  for f in ('alpha-release-cli.mjs','alpha-release.mjs','alpha-profile.mjs'):shutil.copyfile(Path(__file__).parent/f,self.src/f);os.chmod(self.src/f,0o600)
  self.node=self.selected_node;self.files={'nested/a':b'hello','profile.json':b'{}'}
 def tearDown(self):self.temp.cleanup()
 def fixture(self,mutate=lambda v:None,archive_path=None):
  now=__import__('datetime').datetime.now(__import__('datetime').timezone.utc)
  stamp=lambda d:d.isoformat(timespec='milliseconds').replace('+00:00','Z')
  v={'schema':'dsmack-alpha-release/2','key_id':'test','release_id':'test-alpha','channel':'alpha','sequence':2,'issued_at':stamp(now-__import__('datetime').timedelta(minutes=5)),'expires_at':stamp(now+__import__('datetime').timedelta(hours=1)),'platform':{'os':'darwin','arch':'arm64','minimum_version':'15.0'},'app':{'team_id':'DC9JH5DRMY','bundle_id':'dev.dsmack.provider','cdhash_full':'a'*64,'certificate_sha256':'b'*64,'attestation_category':6,'entitlements_sha256':'c'*64,'notarization_evidence_sha256':'d'*64},'files':[{'path':k,'bytes':len(b),'sha256':sha(b),'mode':0o600} for k,b in self.files.items()],'profiles':[{'profile_id':'test','descriptor_path':'profile.json','descriptor_sha256':sha(b'{}')}],'provenance_sha256':'e'*64,'verification_policy':'alpha-category6/1'}
  a=archive_path or self.archive();v['archive']={'format':'tar+gzip' if a.read_bytes().startswith(b'\x1f\x8b') else 'tar','bytes':a.stat().st_size,'sha256':sha(a.read_bytes())}
  mutate(v)
  script="const c=require('node:crypto');const input=JSON.parse(require('node:fs').readFileSync(0));const v=input.inventory;const canon=o=>o===null||typeof o!=='object'?JSON.stringify(o):Array.isArray(o)?'['+o.map(canon).join(',')+']':'{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canon(o[k])).join(',')+'}';const raw=Buffer.from(canon(v));const k=input.testPrivate?{privateKey:c.createPrivateKey(input.testPrivate),publicKey:c.createPublicKey(input.testPrivate)}:c.generateKeyPairSync('ed25519');console.log(JSON.stringify({raw:raw.toString('base64'),signature:c.sign(null,Buffer.concat([Buffer.from(v.schema+'\\0'),raw]),k.privateKey).toString('base64'),publicKey:k.publicKey.export({format:'pem',type:'spki'}),testPrivate:k.privateKey.export({format:'pem',type:'pkcs8'})}));"
  out=json.loads(subprocess.check_output([str(self.node),'-e',script],input=json.dumps({'inventory':v,'testPrivate':getattr(self,'synthetic_test_key',None)}).encode()));self.synthetic_test_key=out['testPrivate'];import base64
  self.inventory=self.root/'inventory.json';self.inventory.write_bytes(base64.b64decode(out['raw']));self.signature=self.root/'signature.bin';self.signature.write_bytes(base64.b64decode(out['signature']));key=self.root/'root.pem';key.write_text(out['publicKey']);os.chmod(key,0o600)
  self.bootstrap={'schema':'dsmack-alpha-bootstrap/1','node':pin(self.node),'sources':{f:pin(self.src/f) for f in ('alpha-release-cli.mjs','alpha-release.mjs','alpha-profile.mjs')},'trust_key':pin(key),'key_id':'test','channel':'alpha','min_sequence':2}
  return v
 def archive(self,kind=None):
  p=self.root/'release.tar'
  with tarfile.open(p,'w',format=tarfile.USTAR_FORMAT) as t:
   for name,b in self.files.items():
    x=tarfile.TarInfo(name);x.size=len(b);t.addfile(x,io.BytesIO(b))
   if kind:
    x=tarfile.TarInfo({'extra':'extra','traversal':'../escape','duplicate':'nested/a'}.get(kind,'link'));x.size=0
    if kind=='symlink':x.type=tarfile.SYMTYPE;x.linkname='/tmp/escape'
    if kind=='fifo':x.type=tarfile.FIFOTYPE
    t.addfile(x,io.BytesIO(b''))
  return p
 def test_actual_signature_authentication_private_atomic_stage_and_retry_refusal(self):
  self.fixture();archive=self.archive();target=self.root/'installed';r=stage(self.bootstrap,self.inventory,self.signature,archive,target)
  self.assertFalse(r['launch_ready']);self.assertEqual((target/'nested/a').read_bytes(),b'hello');self.assertEqual((target/'nested').stat().st_mode&0o777,0o700)
  checked=authenticate(self.bootstrap,self.inventory,self.signature,root=target);self.assertTrue(checked['staged_files_checked'])
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,archive,target)
 def test_unknown_duplicate_traversal_symlink_fifo_refuse(self):
  self.fixture()
  for kind in ['extra','duplicate','traversal','symlink','fifo']:
   with self.subTest(kind=kind):
    p=self.archive(kind);self.fixture(archive_path=p)
    with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,p,self.root/('refused-'+kind))
 def test_wrong_signature_or_rollback_refuse_before_journal(self):
  self.fixture();archive=self.archive();target=self.root/'refused';self.bootstrap['min_sequence']=3
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,archive,target)
  self.assertFalse((self.root/'refused.install-journal.json').exists());self.bootstrap['min_sequence']=2;self.signature.write_bytes(b'0'*64)
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,archive,target)
  self.assertFalse((self.root/'refused.install-journal.json').exists())
 def test_ancestor_file_conflict_and_oversize_refuse_before_writes(self):
  for mutate in [lambda v:v['files'].append({'path':'nested','bytes':0,'sha256':sha(b''),'mode':0o600}),lambda v:v['files'][0].update(bytes=8589934593)]:
   self.fixture(mutate)
   with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,self.archive(),self.root/'refused')
   self.assertFalse((self.root/'refused.install-journal.json').exists())
 def test_persisted_floor_and_same_sequence_equivocation_refuse(self):
  self.fixture();archive=self.archive();stage(self.bootstrap,self.inventory,self.signature,archive,self.root/'installed')
  path=self.root/'alpha-release-state.json';state=json.loads(path.read_text());self.assertEqual(state['minimum_sequence'],2)
  state['minimum_sequence']=3;path.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'persisted rollback'):stage(self.bootstrap,self.inventory,self.signature,archive,self.root/'older')
  state['minimum_sequence']=2;state['inventory_sha256']='f'*64;path.write_text(json.dumps(state))
  with self.assertRaisesRegex(ValueError,'equivocation'):stage(self.bootstrap,self.inventory,self.signature,archive,self.root/'other')
 def test_GNU_longname_is_not_silently_normalized(self):
  self.files={'x'*140:b'hello','profile.json':b'{}'};p=self.root/'gnu.tar'
  with tarfile.open(p,'w',format=tarfile.GNU_FORMAT) as t:
   for name,b in self.files.items():
    x=tarfile.TarInfo(name);x.size=len(b);t.addfile(x,io.BytesIO(b))
  self.fixture(archive_path=p)
  with self.assertRaisesRegex(ValueError,'extension'):stage(self.bootstrap,self.inventory,self.signature,p,self.root/'refused')
 def test_trailing_payload_and_missing_member_refuse_before_install_journal(self):
  self.fixture();p=self.archive();p.write_bytes(p.read_bytes()+b'forbidden trailing payload')
  self.fixture(archive_path=p)
  with self.assertRaisesRegex(ValueError,'trailing'):stage(self.bootstrap,self.inventory,self.signature,p,self.root/'refused')
  self.assertFalse((self.root/'refused.install-journal.json').exists())
  self.files.pop('nested/a');p=self.archive()
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,p,self.root/'missing')
 def test_PAX_headers_refused_before_normalization(self):
  self.fixture();p=self.root/'pax.tar'
  with tarfile.open(p,'w',format=tarfile.PAX_FORMAT) as t:
   for name,b in self.files.items():
    x=tarfile.TarInfo(name);x.size=len(b);x.pax_headers={'comment':'ignored extension'};t.addfile(x,io.BytesIO(b))
  self.fixture(archive_path=p)
  with self.assertRaisesRegex(ValueError,'extension'):stage(self.bootstrap,self.inventory,self.signature,p,self.root/'refused')
 def test_actual_bootstrap_cli_and_readonly_size_plan(self):
  self.fixture();out=self.root/'actual-bootstrap';script=Path(__file__).parent/'alpha-bootstrap.mjs'
  result=json.loads(subprocess.check_output([str(self.node),str(script),'--trust-key',str(self.root/'root.pem'),'--key-id','test','--channel','alpha','--min-sequence','2','--out',str(out)]))
  self.assertFalse(result['launch_ready']);self.assertEqual((out/'node').stat().st_mode&0o777,0o700)
  plan=json.loads(subprocess.check_output(['python3','-I',str(out/'alpha_stage.py'),'--bootstrap',str(out/'bootstrap.json'),'--inventory',str(self.inventory),'--signature',str(self.signature),'--target',str(self.root/'planned'),'--plan']))
  self.assertEqual(plan['expanded_stage_bytes'],7);self.assertFalse(plan['sparse_extraction']);self.assertFalse((self.root/'planned.install-journal.json').exists())
 def test_encoded_duplicate_sparse_and_expanded_total_refuse(self):
  for kind in ('encoded-duplicate','sparse'):
   self.fixture();p=self.archive()
   with tarfile.open(p,'a',format=tarfile.USTAR_FORMAT) as t:
    x=tarfile.TarInfo('nested//a' if kind=='encoded-duplicate' else 'profile.json');x.size=0
    if kind=='sparse':x.type=tarfile.GNUTYPE_SPARSE
    t.addfile(x,io.BytesIO(b''))
   self.fixture(archive_path=p)
   with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,p,self.root/('refused-'+kind))
  def oversized(v):
   v['files'] += [{'path':'large'+str(i),'bytes':8589934592,'sha256':'a'*64,'mode':0o600} for i in range(5)]
  self.fixture(oversized)
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,self.archive(),self.root/'oversize')
 def test_interruption_preserves_private_journal_and_refuses_implicit_retry(self):
  from unittest.mock import patch
  import alpha_stage
  self.fixture();archive=self.archive();target=self.root/'interrupted';real=alpha_stage.authenticate;count=[0]
  def fault(*args,**kwargs):
   count[0]+=1
   if count[0]==2:raise OSError('synthetic post-extraction interruption')
   return real(*args,**kwargs)
  with patch('alpha_stage.authenticate',side_effect=fault):
   with self.assertRaises(OSError):stage(self.bootstrap,self.inventory,self.signature,archive,target)
  self.assertFalse(target.exists());self.assertTrue((self.root/'interrupted.install-journal.json').exists());incoming=list(self.root.glob('.interrupted.incoming-*'));self.assertEqual(len(incoming),1);self.assertEqual(incoming[0].stat().st_mode&0o777,0o700)
  with self.assertRaises(FileExistsError):stage(self.bootstrap,self.inventory,self.signature,archive,target)
 def test_NODE_OPTIONS_cannot_inject_child_code(self):
  from unittest.mock import patch
  self.fixture();marker=self.root/'ENV-INJECTED';hook=self.root/'hook.cjs';hook.write_text("require('node:fs').writeFileSync("+json.dumps(str(marker))+",'bad')")
  with patch.dict(os.environ,{'NODE_OPTIONS':'--require '+str(hook),'NODE_PATH':str(self.root)}):authenticate(self.bootstrap,self.inventory,self.signature)
  self.assertFalse(marker.exists())
 def test_existing_version_is_preserved(self):
  self.fixture();target=self.root/'existing';target.mkdir(mode=0o700);(target/'sentinel').write_bytes(b'keep')
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,self.archive(),target)
  self.assertEqual((target/'sentinel').read_bytes(),b'keep')
 def test_archive_replacement_or_append_after_preflight_refuses(self):
  from unittest.mock import patch
  import alpha_stage
  self.fixture();archive=self.archive();real=alpha_stage._stage_authenticated
  for replace in (False,True):
   original=archive.read_bytes()
   def swapped(*args,**kwargs):
    if replace:
     other=self.root/'replacement.tar';other.write_bytes(original);os.replace(other,archive)
    else:archive.write_bytes(original+b'changed')
    return real(*args,**kwargs)
   target=self.root/('swapped-'+str(replace))
   with patch('alpha_stage._stage_authenticated',side_effect=swapped):
    with self.assertRaisesRegex(ValueError,'archive identity'):stage(self.bootstrap,self.inventory,self.signature,archive,target)
   self.assertFalse(target.exists());archive.write_bytes(original)
 def test_valid_same_root_inventory_substitution_cannot_commit_old_state(self):
  from unittest.mock import patch
  import alpha_stage
  self.fixture();old_raw=self.inventory.read_bytes();old_sig=self.signature.read_bytes();archive=self.archive()
  self.fixture(lambda v:v.update(release_id='different-valid-release'));new_raw=self.inventory.read_bytes();new_sig=self.signature.read_bytes();self.inventory.write_bytes(old_raw);self.signature.write_bytes(old_sig)
  real=alpha_stage.authenticate;calls=[0]
  def substitute(*args,**kwargs):
   calls[0]+=1
   if calls[0]==2:self.inventory.write_bytes(new_raw);self.signature.write_bytes(new_sig)
   return real(*args,**kwargs)
  target=self.root/'inventory-swapped'
  with patch('alpha_stage.authenticate',side_effect=substitute):
   with self.assertRaisesRegex(ValueError,'selected inventory changed'):stage(self.bootstrap,self.inventory,self.signature,archive,target)
  self.assertFalse(target.exists());self.assertFalse((self.root/'alpha-release-state.json').exists())
 def test_real_gzip_archive_preserves_exact_closure(self):
  import gzip
  p=self.root/'release.tar.gz';p.write_bytes(gzip.compress(self.archive().read_bytes()));self.fixture(archive_path=p)
  r=stage(self.bootstrap,self.inventory,self.signature,p,self.root/'gzip-installed');self.assertEqual(r['files'],2)
 def test_bootstrap2_runtime_and_dependency_substitution_refuses(self):
  self.fixture();out=self.root/'runtime-two';script=Path(__file__).parent/'alpha-bootstrap.mjs'
  subprocess.check_output([str(self.node),str(script),'--trust-key',str(self.root/'root.pem'),'--key-id','test','--channel','alpha','--min-sequence','2','--out',str(out)])
  b=json.loads((out/'bootstrap.json').read_bytes());authenticate(b,self.inventory,self.signature)
  original=b['runtime']['node_version'];b['runtime']['node_version']='v99.0.0'
  with self.assertRaisesRegex(ValueError,'runtime/dependency'):authenticate(b,self.inventory,self.signature)
  b['runtime']['node_version']=original;library=self.root/'synthetic-native.dylib';library.write_bytes(b'synthetic dependency');os.chmod(library,0o600);b['runtime']['shared_objects']=sorted(b['runtime']['shared_objects']+[str(library)]);b['runtime_dependencies']=[{'load_path':str(library),**pin(library)}]
  alias=self.root/'native-alias.dylib';alias.symlink_to(library);b['runtime']['shared_objects']=sorted([x for x in b['runtime']['shared_objects'] if x!=str(library)]+[str(alias)]);b['runtime_dependencies']=[{'load_path':str(alias),**pin(library)}]
  with self.assertRaisesRegex(ValueError,'aliases refused'):authenticate(b,self.inventory,self.signature)
  b['runtime']['shared_objects']=sorted([x for x in b['runtime']['shared_objects'] if x!=str(alias)]+[str(library)]);b['runtime_dependencies']=[{'load_path':str(library),**pin(library)}]
  library.write_bytes(b'changed native dependency')
  with self.assertRaises(ValueError):authenticate(b,self.inventory,self.signature)
  b['runtime_dependencies']=[]
  with self.assertRaisesRegex(ValueError,'complete non-system'):authenticate(b,self.inventory,self.signature)
 def test_unpinned_source_and_writable_parent_refuse(self):
  self.fixture();archive=self.archive();self.src.joinpath('alpha-profile.mjs').write_text('throw Error("untrusted");')
  with self.assertRaises(ValueError):stage(self.bootstrap,self.inventory,self.signature,archive,self.root/'refused')
if __name__=='__main__':unittest.main()
