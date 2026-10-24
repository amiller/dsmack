import json,unittest
import diagnose_pinned_cli as d
class Tests(unittest.TestCase):
 def test_private_text_not_exported(self):
  raw=b'\n'.join(json.dumps(e).encode()for e in [{'type':'system','subtype':'init','model':d.MODEL,'private':'SECRET'},{'type':'system','subtype':'api_retry','error_status':401,'error':'SECRET'},{'type':'assistant','message':{'model':d.MODEL,'content':'SECRET'}},{'type':'result','result':'SECRET'}]);r=d.summarize(raw);self.assertNotIn('SECRET',json.dumps(r));self.assertEqual(r['retry_statuses'],[401]);self.assertEqual(r['assistant_events'],1)
 def test_wrong_model_and_malformed_status(self):
  r=d.summarize(b'{"type":"assistant","message":{"model":"other"}}\n{"type":"system","subtype":"api_retry","error_status":true}');self.assertFalse(r['assistant_model_matches']);self.assertEqual(r['retry_statuses'],[None])
 def test_malformed_and_bound(self):
  for raw in [b'[]',b'not json',b'x'*262145]:self.assertTrue(d.summarize(raw)['parse_refused'])
class Bounds(unittest.TestCase):
 def test_event_and_status_metadata_bound(self):
  event=b'{"type":"system","subtype":"api_retry","error_status":503}'
  v=d.summarize(b'\n'.join([event]*1025));self.assertTrue(v['parse_refused']);self.assertEqual(len(v['retry_statuses']),16);self.assertLess(len(json.dumps(v)),4096)
if __name__=='__main__':unittest.main()
