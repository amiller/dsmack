import pathlib,tempfile,unittest,types
from unittest.mock import patch
P=pathlib.Path(__file__).parent
scope={'__name__':'fleet_test','__file__':str(P/'fleet.py')};exec(compile((P/'fleet.py').read_bytes(),str(P/'fleet.py'),'exec'),scope)
class Fleet(unittest.TestCase):
 def test_uncertain_child_cannot_be_reinvoked(self):
  with tempfile.TemporaryDirectory(prefix='.fleet-',dir=pathlib.Path.home())as temp:
   root=pathlib.Path(temp);root.chmod(0o700);config=root/'source.json';scope['exclusive'](config,scope['canonical']({'install_root':str(root/'runtime')}));entry={'name':'undo','config':str(config),'registration':'unused'}
   with patch.object(scope['subprocess'],'run',return_value=types.SimpleNamespace(returncode=1))as child:
    with self.assertRaises(ValueError):scope['cycle'](entry,root,{})
    with self.assertRaises(ValueError):scope['cycle'](entry,root,{})
    self.assertEqual(child.call_count,1)
 def test_empty_queue_keeps_same_unconsumed_state(self):
  with tempfile.TemporaryDirectory(prefix='.fleet-',dir=pathlib.Path.home())as temp:
   root=pathlib.Path(temp);root.chmod(0o700);config=root/'source.json';scope['exclusive'](config,scope['canonical']({'install_root':str(root/'runtime')}));entry={'name':'undo','config':str(config),'registration':'unused'};progress={}
   with patch.object(scope['subprocess'],'run',return_value=types.SimpleNamespace(returncode=0))as child:
    scope['cycle'](entry,root,progress);scope['cycle'](entry,root,progress);self.assertEqual(child.call_count,2);self.assertEqual(progress,{});self.assertFalse((root/'undo0/fleet-child-active.json').exists())
if __name__=='__main__':unittest.main()
