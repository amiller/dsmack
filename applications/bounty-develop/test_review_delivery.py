"""Source controls for closed browser lowering, no browser/VM/provider."""
import base64,json,pathlib,sys,unittest,tempfile,types,tarfile,io
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import prepare_review as p
import build_review as b
class Tests(unittest.TestCase):
 def setUp(self):self.raw={k:b'x'for k in p.SLOTS};self.expected=['1'*64,'2'*64,'3'*64,'4'*64]
 def test_all_roles_exact_closed_credential_free_tuple(self):
  for role in p.SELECTORS:
   raw=dict(self.raw)
   if role!='primary-review':raw['suite']=b'{}'
   m,slots=p.review_manifest({'base_vm':{'os_image_hash':'original'}},raw,self.expected,role);s=json.loads(m['docker_compose_file'])['services']['review']
   self.assertEqual(m['name'],p.SELECTORS[role]);self.assertEqual(m['network']['mode'],'none');self.assertEqual(m['allowed_envs'],[]);self.assertNotIn('credentials',m);self.assertEqual(s['security_profile'],'browser-sandbox-v1');self.assertEqual(m['harness']['sha256'],p.HARNESS);self.assertEqual(s['image'].split('@')[1],p.IMAGE);self.assertTrue(s['read_only']);self.assertEqual(len(m['allowed_files']),len(raw));self.assertEqual(m['base_vm'],{'os_image_hash':'original'})
 def test_measured_target_and_exact_expected_arguments(self):
  m,_=p.review_manifest({},self.raw,self.expected,'primary-review');s=json.loads(m['docker_compose_file'])['services']['review'];self.assertEqual(s['entrypoint'],['/usr/bin/python3','-I','-B']);self.assertEqual(s['command'][0],'/workspace/inputs/driver');self.assertEqual(s['command'][2::2],self.expected)
 def test_unknown_role_refused(self):
  with self.assertRaises(ValueError):p.review_manifest({},self.raw,self.expected,'develop')
 def test_suite_mount_is_required_read_only_workload(self):
  m,_=p.review_manifest({},dict(self.raw,suite=b'{}'),self.expected,'base');row=next(r for r in m['allowed_files']if r['slot']=='suite');self.assertEqual(row,{'slot':'suite','target':'/workspace/inputs/suite','mode':'ro','audience':'workload','required':True,'max_bytes':1048576})
 def test_execution_context_uses_selected_stage_id(self):
  r={'run_id':'a'*32,'attempt_id':'b'*32};e={'files':[{'slot':'request','content_base64':base64.b64encode(json.dumps(r).encode()).decode()}]};self.assertEqual(b.execution_context(e,'a'*32,p.SELECTORS['base'])[1]['attempt_id'],'a'*32)
  with self.assertRaises(ValueError):b.execution_context(e,'b'*32,p.SELECTORS['base'])
 def test_builder_selected_oci_config(self):self.assertEqual(b.IMAGE,p.IMAGE);self.assertEqual(b.CONFIG,'sha256:e36eaa11c766eb715dab6ba41dc82d046365d408175506e0cce55e006adbd06b')
 def test_public_transport_extension_is_closed(self):
  t=types.SimpleNamespace(PUBLIC_CHANNELS=b.ORIGINAL_PUBLIC_CHANNELS,PRIVATE_CHANNELS=('envelopes','broker'));b.enable_public_envelope_channel(t);self.assertEqual(t.PUBLIC_CHANNELS,b.ORIGINAL_PUBLIC_CHANNELS+('public-inputs',))
  with self.assertRaises(ValueError):b.enable_public_envelope_channel(t)
  for channels in [b.ORIGINAL_PUBLIC_CHANNELS+('broker',),('public-inputs',)]:
   with self.assertRaises(ValueError):b.enable_public_envelope_channel(types.SimpleNamespace(PUBLIC_CHANNELS=channels,PRIVATE_CHANNELS=('envelopes','broker')))
 def test_actual_original_packer_omission_and_repaired_membership(self):
  if sys.platform!='linux':self.skipTest('actual sealed original public packer requires Linux')
  from transport_loader import load
  root=pathlib.Path(__file__).resolve().parents[2]
  t=load(root/'base-vm/browser-sandbox-v1/source/smoke/launch_vm_dstack_arm64.py');payload=b'{"public":"fixture"}';selector='fixture-review'
  with tempfile.TemporaryDirectory()as tmp:
   r=pathlib.Path(tmp);tree=r/'tree';tree.mkdir();(tree/'public-inputs').mkdir();(tree/'public-inputs'/(selector+'.envelope.json')).write_bytes(payload);(tree/'WORKLOAD').write_text(selector+'\n');t.start_overall_deadline(60)
   t.build_workload_disk(None,str(tree),str(r/'old.img'),1048576)
   with self.assertRaisesRegex(ValueError,'missing from packed disk'):b.verify_packed_public_envelope(r/'old.img',selector,payload)
   b.enable_public_envelope_channel(t);t.build_workload_disk(None,str(tree),str(r/'new.img'),1048576)
   self.assertEqual(b.verify_packed_public_envelope(r/'new.img',selector,payload),b.sha(payload))
 def test_packed_envelope_wrong_duplicate_link_and_private_refused(self):
  target='public-inputs/fixture-review.envelope.json';payload=b'{}'
  with tempfile.TemporaryDirectory()as tmp:
   for mode in ['wrong','duplicate','link','private']:
    path=pathlib.Path(tmp)/(mode+'.tar')
    with tarfile.open(path,'w',format=tarfile.USTAR_FORMAT)as archive:
     m=tarfile.TarInfo(target);raw=b'xx'if mode=='wrong'else payload;m.size=len(raw)
     if mode=='link':m.type=tarfile.SYMTYPE;m.linkname='elsewhere';m.size=0;archive.addfile(m)
     else:archive.addfile(m,io.BytesIO(raw))
     if mode=='duplicate':archive.addfile(m,io.BytesIO(raw))
     if mode=='private':m=tarfile.TarInfo('broker/no-secrets-fixture');m.size=0;archive.addfile(m,io.BytesIO(b''))
    with self.assertRaises(ValueError):b.verify_packed_public_envelope(path,'fixture-review',payload)
if __name__=='__main__':unittest.main()
