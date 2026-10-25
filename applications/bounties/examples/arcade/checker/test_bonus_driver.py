import base64,contextlib,hashlib,io,json,os,pathlib,runpy,shutil,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
d=runpy.run_path(str(ROOT/'bonus_guest_driver.py'));f=runpy.run_path(str(ROOT/'task_factory.py'));canonical=d['canonical'];slug='puzzle-deadlock-testnet-1'
class Driver(unittest.TestCase):
 def setUp(self):self.previous_umask=os.umask(0o077)
 def tearDown(self):os.umask(self.previous_umask)
 def test_negative_outcomes_export_and_factory_rejects(self):
  for baseline,candidate in [('functional_failure','functional_failure'),('passed','passed'),('functional_failure','infrastructure_failure')]:
   with self.subTest(baseline=baseline,candidate=candidate),tempfile.TemporaryDirectory(dir=pathlib.Path.home())as temp:
    root=pathlib.Path(temp);inputs=root/'inputs';state=root/'state';art=root/'artifacts'
    for p in (inputs,state,art):p.mkdir(mode=0o700)
    base={'app.txt':b'base'};changed={'app.txt':b'candidate'};dig=lambda files:f['tree_digest'](files)
    for name,files in [('base.json',base),('candidate.json',changed)]: (inputs/name).write_bytes(canonical({n:base64.b64encode(b).decode()for n,b in files.items()}))
    (inputs/'base-files.json').write_bytes(canonical({'task_slug':slug}));(inputs/'request.json').write_bytes(canonical({'base_tree_sha256':dig(base),'candidate_tree_sha256':dig(changed)}))
    def checker(argv,**kwargs):
     out=pathlib.Path(argv[argv.index('--out')+1]);role='baseline'if 'baseline'in out.name else'candidate';outcome=baseline if role=='baseline'else candidate;media=[]
     for name,body in [('final.png',b'\x89PNG\r\n\x1a\nfixture'),('trace.zip',b'PKfixture'),('video.webm',b'\x1aE\xdf\xa3fixture')]:
      (out/name).write_bytes(body);media.append({'name':name,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
     tests=[{'id':str(i),'status':'passed'}for i in range(7)]if outcome=='passed'else[{'id':'feature','status':'assertion_failed'if outcome=='functional_failure'else'infrastructure_failure'}]
     result={'schema':'dsmack-arcade-checker-result/1','task_slug':slug,'base_commit':f['BASE'],'outcome':outcome,'passed':outcome=='passed','tests':tests,'candidate_tree_sha256':dig(base if role=='baseline'else changed),'artifacts':media}
     (out/'checker-result.json').write_bytes(canonical(result));return types.SimpleNamespace(returncode={'passed':0,'functional_failure':3,'infrastructure_failure':4}[outcome],stdout=b'{}',stderr=b'')
    with patch.object(d['subprocess'],'run',checker),contextlib.redirect_stdout(io.StringIO()):d['run'](inputs,state,art)
    self.assertEqual(set(p.name for p in art.iterdir()),{role+'-'+name for role in ('baseline','candidate')for name in ('checker-result.json','final.png','trace.zip','video.webm')})
    retained=root/'retained';(retained/'outputs').mkdir(parents=True,mode=0o700);(retained/'outputs/artifacts').mkdir(mode=0o700)
    for p in art.iterdir():shutil.copyfile(p,retained/'outputs/artifacts'/p.name.replace('.','-'))
    rows=[{'name':p.name.replace('.','-'),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in art.iterdir()];(retained/'receipt.json').write_bytes(canonical({'outputs':{'artifacts':rows}}))
    job=root/'join';job.mkdir(mode=0o700)
    with patch.dict(f['check_authenticated_outputs'].__globals__,git_tree=lambda *_:base,checker_digest=lambda _:'fixture-checker'):
     result=f['check_authenticated_outputs']({'task_slug':slug,'repository':'unused','policy_sha256':'fixture-policy'},{'selection':{'candidate_sha256':dig(changed),'policy_sha256':'fixture-policy'},'retained':str(retained)},job)
    self.assertFalse(result['functional_passed'])
 def test_missing_media_refuses_completion(self):
  with tempfile.TemporaryDirectory(dir=pathlib.Path.home())as temp:
   root=pathlib.Path(temp);inputs=root/'inputs';state=root/'state';art=root/'art'
   for p in (inputs,state,art):p.mkdir(mode=0o700)
   files={'app.txt':b'base'};digest=f['tree_digest'](files);body=canonical({'app.txt':base64.b64encode(b'base').decode()})
   for name in ('base.json','candidate.json'):(inputs/name).write_bytes(body)
   (inputs/'base-files.json').write_bytes(canonical({'task_slug':slug}));(inputs/'request.json').write_bytes(canonical({'base_tree_sha256':digest,'candidate_tree_sha256':digest}))
   def checker(argv,**kwargs):
    out=pathlib.Path(argv[argv.index('--out')+1]);(out/'checker-result.json').write_bytes(canonical({'schema':'dsmack-arcade-checker-result/1','task_slug':slug,'outcome':'passed','passed':True,'candidate_tree_sha256':digest,'tests':[{'id':str(i),'status':'passed'}for i in range(7)],'artifacts':[]}));return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
   with patch.object(d['subprocess'],'run',checker),self.assertRaisesRegex(ValueError,'complete media'):d['run'](inputs,state,art)
   self.assertFalse(any(art.iterdir()))
if __name__=='__main__':unittest.main()
