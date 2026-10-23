"""Offline constructor controls; synthetic OCI is NEVER an actual selection."""
import argparse,copy,importlib.util,json,pathlib,sys,unittest
p=pathlib.Path(__file__).parent/'reference/paid480_policy.py';spec=importlib.util.spec_from_file_location('policy480',p);c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class Controls(unittest.TestCase):
 def setUp(self):
  self.originals={k:(FIXTURES/n).read_bytes() for k,n in [('policy','policy.json'),('terms','terms.json'),('harness','harness.json'),('recipe_closure','recipe-closure.json')]}
  self.generator=(p.parents[2]/'bounty-judges/generate.py').read_bytes()
  self.image={'schema':'dsmack-paid480-generator-image/1','parent_oci_manifest_sha256':c.PARENT_IMAGE,'oci_manifest_sha256':'d57ab5ad98dca0a2a62a8a0bf84fda4de8ccf6d3f482ddf29606e9ddc800b144','oci_config_sha256':'a36c147163224aa199dc2ee32e9f7a1a720271faef3973ddf09a9b5070f6c578','generator_source_sha256':c.GENERATOR,'changed_files':['opt/bounty-judges/generate.py'],'unchanged_parent_layers_preserved':True,'original_derivation':{'path':'/OFFLINE-SYNTHETIC/DERIVATION.json','bytes':1,'sha256':c.sha(b'fixture')}}
  self.recipe=json.loads((p.parents[2]/'bounty-judges/generation-recipe-paid480.json').read_bytes());self.recipe['derived_generator_oci_manifest_sha256']=self.image['oci_manifest_sha256']
 def run_constructor(self):
  raw=c.canonical(self.image);return c.construct(self.originals,raw,c.sha(raw),self.generator,c.canonical(self.recipe))
 def test_coherent_closures_and_unchanged_acceptance(self):
  result=self.run_constructor();policy=json.loads(result['acceptance-policy.json']);terms=json.loads(result['task-terms.json']);h=json.loads(result['HARNESS-CLOSURE.json']);closure=json.loads(result['RECIPE-SOURCE-CLOSURE.json'])
  self.assertEqual(terms['checker_sha256'],c.sha(result['acceptance-policy.json']));self.assertEqual(terms['harness_sha256'],policy['harness_closure_sha256']);self.assertEqual(policy['recipe_closure_sha256'],h['recipe_source_closure_sha256']);self.assertEqual(policy['acceptance']['judge_generation']['model_wall_seconds'],480)
  self.assertNotIn('infrastructure_retry_policy',policy['acceptance']['judge_generation'])
  old=json.loads(self.originals['policy'])
  for key in ['all_required','generation_count','browser_ci_count','primary_count','primary','suite_evaluation']:self.assertEqual(policy['acceptance'][key],old['acceptance'][key])
  self.assertEqual([r for r in closure['files']if r['path']=='applications/bounty-judges/generate.py'][0]['sha256'],c.GENERATOR)
 def test_old_oci_refused(self):
  self.image['oci_manifest_sha256']=c.PARENT_IMAGE
  with self.assertRaises(ValueError):self.run_constructor()
 def test_wrong_generator_source_refused(self):
  self.generator+=b'\n'
  with self.assertRaises(ValueError):self.run_constructor()
 def test_wrong_wall_or_recipe_image_refused(self):
  for field,value in [('model_wall_seconds',180),('outer_stage_wall_seconds',240),('native_vm_wall_seconds',550),('max_turns',3)]:
   with self.subTest(field=field):
    old=self.recipe['bounds'][field];self.recipe['bounds'][field]=value
    with self.assertRaises(ValueError):self.run_constructor()
    self.recipe['bounds'][field]=old
  self.recipe['derived_generator_oci_manifest_sha256']=c.PARENT_IMAGE
  with self.assertRaises(ValueError):self.run_constructor()
 def test_original_hash_substitution_refused(self):
  self.originals['policy']+=b'\n'
  with self.assertRaises(ValueError):self.run_constructor()
 def test_external_actual_descriptor_pin_required(self):
  with self.assertRaises(ValueError):c.construct(self.originals,c.canonical(self.image),c.sha(b'other'),self.generator,c.canonical(self.recipe))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--originals',type=pathlib.Path,default=pathlib.Path(__file__).parent/'fixtures/paid480/originals');a=ap.parse_args();FIXTURES=a.originals;unittest.main(argv=[sys.argv[0]])
