import importlib.util,json,pathlib,tempfile,unittest,hashlib,urllib.request,urllib.error
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check.py'));c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class Guards(unittest.TestCase):
 def test_scope_package_and_test_mutations(self):
  with tempfile.TemporaryDirectory()as d:
   root=pathlib.Path(d);base={'package.json':b'fixed','apps/board/test/search.js':b'trusted',**{p:b'base'for p in c.ALLOWED}}
   (root/'base-files.json').write_text(json.dumps({'files':{p:c.sha(b)for p,b in base.items()}}))
   with patch.object(c,'HERE',root):
    self.assertEqual(c.validate(base,base)[0],[])
    valid={**base,'apps/board/ui.js':b'own patch'};self.assertEqual(c.validate(base,valid)[0],['apps/board/ui.js'])
    for name in ['package.json','apps/board/test/search.js']:
     with self.assertRaisesRegex(c.Invalid,'scope'):c.validate(base,{**base,name:b'fake pass'})
    with self.assertRaisesRegex(c.Invalid,'file_set'):c.validate(base,{**base,'../escape':b'x'})
 def test_symlink_hardlink_and_extra_file_refused(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d);(p/'ordinary').write_text('x');(p/'link').symlink_to(p/'ordinary')
   with self.assertRaises(c.Invalid):c.tree(p)
   (p/'link').unlink();import os;os.link(p/'ordinary',p/'hard')
   with self.assertRaises(c.Invalid):c.tree(p)
 def test_no_candidate_server_write_or_traversal(self):
  server=c.serve({p:b'fixed'for p in c.ALLOWED});origin='http://127.0.0.1:'+str(server.server_port)
  try:
   self.assertEqual(urllib.request.urlopen(origin+'/apps/board/ui.js').read(),b'fixed')
   for path in ['/../package.json','/%2e%2e/package.json','/apps/board/ui.js?fake=1']:
    with self.assertRaises(urllib.error.HTTPError):urllib.request.urlopen(origin+path)
   with self.assertRaises(urllib.error.HTTPError):urllib.request.urlopen(urllib.request.Request(origin+'/apps/board/ui.js',data=b'fakepass',method='POST'))
  finally:server.shutdown();server.server_close()
 def test_fake_pass_timeout_missing_or_wrong_checks_not_pass(self):
  full={'outcome':'passed','tests':[{'id':x,'status':'passed'}for x in c.TESTS]}
  self.assertEqual(c.classify(full,0)[0],'passed')
  for obj,code in [({'outcome':'passed','tests':[]},0),(full,124),(full,4),({**full,'outcome':'infrastructure_failure'},0)]:self.assertNotEqual(c.classify(obj,code)[0],'passed')
  for tests in [[{'id':'fake','status':'passed'}],full['tests'][::-1],full['tests']*2]:
   with self.assertRaises(RuntimeError):c.classify({'outcome':'passed','tests':tests},0)
 def test_actual_owned_process_deadline_reaps(self):
  import os,sys,time
  start=time.monotonic()
  with self.assertRaisesRegex(RuntimeError,'checker_deadline'):
   c.bounded_browser([sys.executable,'-I','-c','import time;time.sleep(30)'],{'PATH':'/usr/bin:/bin'},deadline=.05)
  self.assertLess(time.monotonic()-start,4)
 def test_typed_baseline_assertion_not_infrastructure(self):
  v={'outcome':'functional_failure','tests':[{'id':c.TESTS[0],'status':'passed'},{'id':c.TESTS[1],'status':'assertion_failed'}]}
  self.assertEqual(c.classify(v,3)[0],'functional_failure');self.assertEqual(c.classify(v,4)[0],'infrastructure_failure')
if __name__=='__main__':unittest.main()
