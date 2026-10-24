import base64,importlib.util,json,pathlib,unittest
spec=importlib.util.spec_from_file_location('build_public',pathlib.Path(__file__).with_name('build_public.py'));b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
class Tests(unittest.TestCase):
 def projection(self,run_id='1'*32,attempt_id='2'*32):return {'files':[{'slot':'request','content_base64':base64.b64encode(json.dumps({'run_id':run_id,'attempt_id':attempt_id}).encode()).decode()}]}
 def test_distinct_execution_assignment(self):
  request,context=b.execution_context(self.projection(),'1'*32);self.assertEqual(request['attempt_id'],'2'*32);self.assertEqual(context['attempt_id'],'1'*32)
 def test_wrong_run_or_reused_assignment_refused(self):
  for projection,eid in [(self.projection(),'3'*32),(self.projection(attempt_id='1'*32),'1'*32),(self.projection(),'bad'),(self.projection(),'A'*32)]:
   with self.assertRaises(ValueError):b.execution_context(projection,eid)
 def test_duplicate_request_slot_refused(self):
  p=self.projection();p['files']*=2
  with self.assertRaises(ValueError):b.execution_context(p,'1'*32)
if __name__=='__main__':unittest.main()
