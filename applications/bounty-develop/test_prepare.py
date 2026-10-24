import importlib.util,json,pathlib,tempfile,unittest
spec=importlib.util.spec_from_file_location('prepare',pathlib.Path(__file__).with_name('prepare.py'));p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Tests(unittest.TestCase):
 def setUp(self):self.raw={n:b'x'for n in p.SLOTS};self.expected=['1'*64,'2'*64,'3'*64,'4'*64]
 def test_closed_broker_contract(self):
  m,_=p.configure({'base_vm':{'os_image_hash':'d9'},'runner':{}},self.raw,self.expected)
  self.assertEqual(m['allowed_envs'],[{'audience':'broker','name':'CLAUDE_SUBSCRIPTION_OAUTH'}]);self.assertEqual(m['required_envs'],['CLAUDE_SUBSCRIPTION_OAUTH']);self.assertEqual(m['credentials'],p.credential_contract());self.assertEqual(m['runtime_inputs']['user_config']['mode'],'none');self.assertEqual(m['network']['mode'],'nat')
 def test_exact_measured_command(self):
  m,_=p.configure({},self.raw,self.expected);s=json.loads(m['docker_compose_file'])['services']['develop'];self.assertEqual(s['entrypoint'],['/usr/bin/python3','-I','-B']);self.assertEqual(s['command'][0],'/workspace/inputs/driver');self.assertEqual(s['command'][2::2],self.expected);self.assertTrue(s['read_only']);self.assertNotIn('security_profile',s);self.assertNotIn('privileged',s);self.assertNotIn('pid',s);self.assertEqual(s['image'].split('@')[1],p.IMAGE)
 def test_all_slots_readonly_required(self):
  m,_=p.configure({},self.raw,self.expected);self.assertEqual(len(m['allowed_files']),8)
  for row in m['allowed_files']:self.assertTrue(row['required']);self.assertEqual(row['mode'],'ro');self.assertEqual(row['audience'],'workload')
 def test_three_outputs_and_bounds(self):
  m,_=p.configure({},self.raw,self.expected);self.assertEqual([x['name']for x in m['outputs']['artifacts']],['result-files','stage-checks','public-input-audit']);self.assertEqual(m['limits'],{'timeout_s':550,'workspace_max_bytes':67108864,'output_max_bytes':16777216})
 def test_selected_base_unchanged(self):
  base={'cmdline':'original','os_image_hash':'original'};m,_=p.configure({'base_vm':base},self.raw,self.expected);self.assertEqual(m['base_vm'],base)
 def test_read_regular_cap_link(self):
  with tempfile.TemporaryDirectory()as d:
   f=pathlib.Path(d)/'a';f.write_bytes(b'x');self.assertEqual(p.read(f,1),b'x')
   with self.assertRaises(ValueError):p.read(f,0)
   l=pathlib.Path(d)/'link';l.symlink_to(f)
   with self.assertRaises(OSError):p.read(l,1)
   h=pathlib.Path(d)/'hard';h.hardlink_to(f)
   with self.assertRaises(ValueError):p.read(f,1)
if __name__=='__main__':unittest.main()
