import pathlib,runpy,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
f=runpy.run_path(str(ROOT/'task_factory.py'))
class Profiles(unittest.TestCase):
 def test_projection_keeps_other_apps_and_package_from_base(self):
  base={p:b'base'for app in ('board','puzzle','routes')for p in ('apps/'+app+'/index.html','apps/'+app+'/logic.js','apps/'+app+'/ui.js')};base['package.json']=b'base scripts'
  submitted={p:b'candidate'for p in base}
  for slug,app in [('board-undo-testnet-1','board'),('puzzle-deadlock-testnet-1','puzzle'),('routes-segments-testnet-1','routes')]:
   allowed,_=f['task_projection']({'task_slug':slug});result=f['project_candidate'](base,submitted,allowed)
   self.assertEqual(result['apps/'+app+'/logic.js'],b'candidate');self.assertEqual(result['package.json'],b'base scripts')
   for other in set(('board','puzzle','routes'))-{app}:self.assertEqual(result['apps/'+other+'/logic.js'],b'base')
 def test_wrong_checker_profile_refused_before_build(self):
  with patch.dict(f['checker_files'].__globals__,selected=lambda d:b'{"task_slug":"board-undo-testnet-1"}'if d=='metadata'else b'dummy'):
   with self.assertRaisesRegex(ValueError,'checker task identity'):f['checker_files']({'task_slug':'routes-segments-testnet-1','checker':{'check.py':'code','browser.mjs':'browser','base-files.json':'metadata'}})
 def test_prepared_profile_is_self_contained_and_original_default_remains(self):
  for slug in ('board-search-testnet-1','board-undo-testnet-1','puzzle-deadlock-testnet-1','routes-segments-testnet-1'):
   with tempfile.TemporaryDirectory(dir=pathlib.Path.home())as temp:
    out=f['prepare_checker'](slug,pathlib.Path(temp)/'checker');m=runpy.run_path(str(out/'check.py'));m['select_profile']();self.assertEqual(m['select_profile'].__globals__['TASK_SLUG'],slug)
if __name__=='__main__':unittest.main()
