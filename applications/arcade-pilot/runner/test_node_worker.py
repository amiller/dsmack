import sys,tempfile,unittest
from pathlib import Path

class NodeRouting(unittest.TestCase):
 def test_same_short_directory_is_used_for_materialize_and_prepare(self):
  source=Path(__file__).with_name('node_worker.py');scope={'__name__':'node_test','__file__':str(source)}
  exec(compile(source.read_bytes(),str(source),'exec'),scope)
  with tempfile.TemporaryDirectory(prefix='.arcade-node-',dir=Path.home())as temp:
   root=Path(temp);root.chmod(0o700);attempt='a'*32;native='b'*32;key='test-key'
   cfg={'api_url':'https://example.com','state_dir':str(root)};reg={'key_id':key,'node_capability':'c'*43}
   # Use a short owned root for this no-runtime routing control.
   scope['p']['task_directory']=lambda parent,aid:Path(parent)/('a-'+aid[:12])
   expected=scope['p']['task_directory'](root,attempt)
   class API:
    def __init__(self,*args):pass
    def request(self,*args):return {'attempt_id':attempt,'execution':{'attempt_id':attempt,'key_id':key,'native_execution_id':native}}
   scope['c']['API']=API;scope['c']['state']=lambda path:cfg if path=='config'else reg
   def materialize(config,packet,key_id,parent,fetch):
    expected.mkdir(mode=0o700);task=expected/'task.json';task.write_text('{}');return task
   API.fetch=lambda *args:None;scope['p']['materialize']=materialize
   class Prepared(Exception):pass
   def coordinator(config,command,task,run_parent,identity):
    self.assertEqual(command,'prepare');self.assertEqual(Path(run_parent),expected)
    self.assertEqual(Path(task),expected/'task.json');self.assertEqual(identity,native)
    raise Prepared()
   scope['p']['coordinator']=coordinator;old=sys.argv
   try:
    sys.argv=[str(source),'--config','config','--registration','registration']
    with self.assertRaises(Prepared):scope['main']()
   finally:sys.argv=old

if __name__=='__main__':unittest.main()
