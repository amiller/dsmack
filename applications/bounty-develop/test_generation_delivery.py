"""Synthetic delivery wiring controls; never imports credentials or calls provider."""
import base64,importlib.util,json,pathlib,sys,unittest
root=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(root))
import build_generation as b
import stage_generation_private as private
class Tests(unittest.TestCase):
 def test_execution_id_separate_from_assignment(self):
  r={'run_id':'a'*32,'attempt_id':'b'*32};p={'files':[{'slot':'request','content_base64':base64.b64encode(json.dumps(r).encode()).decode()}]}
  self.assertEqual(b.execution_context(p,'a'*32)[1]['attempt_id'],'a'*32)
  with self.assertRaises(ValueError):b.execution_context(p,'b'*32)
 def test_private_argument_error_is_value_free(self):
  with self.assertRaisesRegex(ValueError,'^argument contract refused$'):private.ValueFreeArguments().parse_args(['secret-never-echoed'])
if __name__=='__main__':unittest.main()
