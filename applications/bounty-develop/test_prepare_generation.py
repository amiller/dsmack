import importlib.util,json,pathlib,unittest
spec=importlib.util.spec_from_file_location('prepare_generation',pathlib.Path(__file__).with_name('prepare_generation.py'));g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
class Tests(unittest.TestCase):
 def result(self):return {'role':'generate','request':{'judge_index':1,'stage_id':'generate-1','requested_model':'claude-opus-4-8','oci_manifest_sha256':g.IMAGE.split(':')[1],'source_tree_sha256':g.BASE_TREE,'input_suite_sha256':None},'stage_profile':{'specification':{'sha256':'1'*64}}}
 def test_three_indices(self):
  for i in (1,2,3):
   r=self.result();r['request'].update(judge_index=i,stage_id='generate-'+str(i));g.generation_request(r,'1'*64)
 def test_wrong_role_candidate_model_suite(self):
  for key,value in [('judge_index',True),('judge_index',4),('stage_id','generate-2'),('requested_model','opus'),('oci_manifest_sha256','0'*64),('source_tree_sha256','0'*64),('input_suite_sha256','0'*64)]:
   r=self.result();r['request'][key]=value
   with self.assertRaises(ValueError):g.generation_request(r,'1'*64)
  r=self.result();r['role']='candidate'
  with self.assertRaises(ValueError):g.generation_request(r,'1'*64)
 def test_specification_fixed(self):
  with self.assertRaises(ValueError):g.generation_request(self.result(),'2'*64)
 def test_manifest_closed_private_channel(self):
  m,_=g.generation_manifest({'base_vm':{'os_image_hash':'original'}},{n:b'x'for n in g.SLOTS},['1'*64]*4);self.assertEqual(m['name'],g.SELECTOR);service=json.loads(m['docker_compose_file'])['services']['generate'];self.assertEqual(service['image'],'127.0.0.1:5005/dsmack-bounty-generator-v1@'+g.IMAGE);self.assertEqual(service['command'][0],'/workspace/inputs/driver');self.assertEqual(m['required_envs'],['CLAUDE_SUBSCRIPTION_OAUTH']);self.assertEqual(m['network']['mode'],'nat');self.assertNotIn('security_profile',service);self.assertEqual(len(m['allowed_files']),8)
if __name__=='__main__':unittest.main()
