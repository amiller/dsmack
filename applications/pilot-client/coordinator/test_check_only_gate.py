"""Real-format synthetic final-gate controls; no VM, credentials or provider."""
import copy,json,unittest
from pathlib import Path
import test_coordinator as fixture
d=fixture.d
class CheckOnlyGate(unittest.TestCase):
 @classmethod
 def setUpClass(cls):fixture.Tests.setUpClass.__func__(cls)
 @classmethod
 def tearDownClass(cls):fixture.Tests.tearDownClass.__func__(cls)
 tools=fixture.Tests.tools
 def readonly_policy(self,value=True):
  p=copy.deepcopy(self.p);old=json.loads(Path(p['reviews']['final']['path']).read_text());old.pop('approved_for_signing_and_live_qualification');old['approved_for_check_only']=value
  p['reviews']['final']=self.file('TEST-ONLY-readonly-final.json',json.dumps(old).encode());return p
 def test_readonly_gate_accepted_only_for_explicit_readonly_validation(self):
  p=self.readonly_policy();d.validate(p,self.m,'run',self.tools,check_only=True)
  with self.assertRaises(d.Refused):d.validate(p,self.m,'run',self.tools)
  for value in [False,1,None]:
   with self.assertRaises(d.Refused):d.validate(self.readonly_policy(value),self.m,'run',self.tools,check_only=True)
 def test_execute_rechecks_live_gate_before_any_side_effect(self):
  p=self.readonly_policy();v=d.validate(p,self.m,'run',self.tools,check_only=True)
  with self.assertRaises(d.Refused):d.execute(p,self.m,'run',v)
  self.assertFalse((self.root/'attempt.logs').exists());self.assertFalse((self.root/'attempt.session.json').exists());self.assertFalse((self.root/'attempt.helper').exists());self.assertFalse((self.root/'attempt').exists())
 def test_existing_live_approval_still_allows_readonly_and_exact_handoff_required(self):
  d.validate(copy.deepcopy(self.p),self.m,'run',self.tools,check_only=True)
  p=self.readonly_policy();g=json.loads(Path(p['reviews']['final']['path']).read_text());g['exact_candidate_pins']['selected_handoff_sha256']='0'*64;p['reviews']['final']=self.file('TEST-ONLY-wrong-readonly-final.json',json.dumps(g).encode())
  with self.assertRaises(d.Refused):d.validate(p,self.m,'run',self.tools,check_only=True)
if __name__=='__main__':unittest.main()
