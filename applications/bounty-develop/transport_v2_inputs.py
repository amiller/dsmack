"""Closed V2 PUBLIC host assembly only. Never fund, claim, import or execute.

The externally selected config and actual-qualified-base descriptor remain root
choices; reconstructing bytes is not evidence of base qualification or funding.
Legacy defaults are never mutated; each selection gets a fresh module namespace.
"""
import hashlib,json,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PINS={'reference/transport_v2_policy.py':'9deaa2276f20ae3eef23710be78afe4b2a05aeb9027aac0b08d9b3c2924437a4','acceptance_inputs.py':'03ae73a6fb0bf3c7f72c9f5442fc1706d5ed300a8d361fd737b528b1d0a3cb56'}
NAMES={'qualified_base','original_policy','original_first','original_second','policy','first_terms','second_terms'}
IDS={'first':'board-search-opus48-transport-v2','second':'board-search-opus48-transport-v2-repeat-2'}
def need(v,m):
 if not v:raise ValueError(m)
def load(name):
 b=(HERE/name).read_bytes();need(hashlib.sha256(b).hexdigest()==PINS[name],'reviewed host source pin');m=types.ModuleType('selected_v2_'+name.replace('/','_'));m.__file__=str(HERE/name);exec(compile(b,m.__file__,'exec'),m.__dict__);return m

def validate_selection(raw,expected,documents):
 c=load('reference/transport_v2_policy.py');c.digest(expected);need(c.sha(raw)==expected,'external public selection hash');v=c.parse(raw)
 need(type(v)is dict and c.canonical(v)==raw and set(v)=={'schema','files'}and v['schema']=='dsmack-transport-v2-funding-selection/1'and type(v['files'])is dict and set(v['files'])==NAMES,'closed canonical public selection')
 need(type(documents)is dict and set(documents)==NAMES,'closed selected document bytes')
 for name,d in v['files'].items():
  need(type(d)is dict and set(d)=={'path','bytes','sha256'}and type(d['path'])is str and Path(d['path']).is_absolute()and type(d['bytes'])is int and 0<d['bytes']<=1048576,'public descriptor');c.digest(d['sha256']);b=documents[name];need(type(b)is bytes and len(b)==d['bytes']and c.sha(b)==d['sha256'],'selected public document')
 out=c.construct(documents['qualified_base'],v['files']['qualified_base']['sha256'],{n:documents['original_'+n]for n in ('policy','first','second')})
 for role,name in [('policy','acceptance-policy.json'),('first_terms','first-task-terms.json'),('second_terms','second-task-terms.json')]:need(documents[role]==out[name],'exact approved V2 derivative')
 return c,v

def read_selection(path,expected):
 c=load('reference/transport_v2_policy.py');raw=c.read(path,65536);need(c.sha(raw)==expected,'external selection hash');v=c.parse(raw);need(type(v)is dict and set(v)=={'schema','files'}and type(v['files'])is dict and set(v['files'])==NAMES,'closed selection before reads')
 docs={}
 for name,d in v['files'].items():
  need(type(d)is dict and set(d)=={'path','bytes','sha256'}and type(d['path'])is str and Path(d['path']).is_absolute(),'public path descriptor');docs[name]=c.read(d['path'],1048576)
 validate_selection(raw,expected,docs);return raw,docs

class Selected:
 def __init__(self,raw,expected,documents,case):
  need(case in IDS,'two V2 cases only');self.c,self.config=validate_selection(raw,expected,documents);self.documents=dict(documents);self.case=case;self.terms=documents[case+'_terms'];self.policy=documents['policy'];self.a=load('acceptance_inputs.py')
  self.a.POLICY=self.c.sha(self.policy);self.a.TERMS=self.c.sha(documents['first_terms']);self.a.REPEAT_TERMS=self.c.sha(documents['second_terms'])
  def identity(which):
   need(type(which)is str and which in ('first','repeat-2'),'closed internal case');name='first'if which=='first'else'second';return self.c.sha(documents[name+'_terms']),IDS[name]
  self.a.case_identity=identity;self.internal='first'if case=='first'else'repeat-2'
 def claim(self,claim):
  self.a.p.keys(claim,('task_id','attempt_id','attempt_nonce','payee'),'selected actual claim');need(claim['task_id']==IDS[self.case]and claim['payee']=='0x0923ed168ed888098815c4e08e48e5caeecedadb','selected case/worker');self.a.p.sha(claim['attempt_nonce'],'claim nonce');need(type(claim['attempt_id'])is str and self.a.re.fullmatch('[a-f0-9]{32}',claim['attempt_id']),'claim ID')
 def plan(self,claim,specification,run_ids):
  self.claim(claim);return self.a.plan(self.terms,self.policy,claim,specification,run_ids,case=self.internal)
 def assemble(self,plan_raw,expected_plan_sha,stage_id,driver_raw,base_manifest,base_bundle,**kw):
  value=self.a.selected_plan(plan_raw,expected_plan_sha);self.claim(value['claim']);need(value.get('case','first')==self.internal,'selected case plan');return self.a.assemble(plan_raw,expected_plan_sha,stage_id,self.terms,self.policy,driver_raw,base_manifest,base_bundle,**kw)
 def develop(self,claim,run_id,driver_raw,base_manifest,base_bundle):
  self.claim(claim);a=self.a;p=a.p;policy=self.c.parse(self.policy);terms=self.c.parse(self.terms);need(type(run_id)is str and a.re.fullmatch('[a-f0-9]{32}',run_id)and run_id!=claim['attempt_id'],'fresh native execution ID');a.source.decode_source(base_bundle,base_manifest,a.BASE);need(self.c.sha(driver_raw)==policy['development']['driver_sha256'],'fixed develop driver')
  request={'schema':p.REQUEST_SCHEMA,'task_id':IDS[self.case],'task_terms_sha256':self.c.sha(self.terms),'attempt_id':claim['attempt_id'],'attempt_nonce':claim['attempt_nonce'],'run_id':run_id,'run_role':'develop','acceptance_profile_sha256':self.c.sha(self.policy),'base':{'repo':'https://github.com/'+terms['repo'],'commit':terms['base_commit'],'tree_manifest_sha256':a.BASE},'candidate':None,'toolchain':{'platform':'linux/arm64','image_digest':policy['images']['develop_oci']},'required_artifacts':a.ARTIFACTS};p.validate_request(request)
  profile=a.canonical(policy['development']['profile']);plan=a.canonical({'schema':'dsmack-bounty-develop-selection/1','task_id':IDS[self.case],'task_terms_sha256':self.c.sha(self.terms),'acceptance_policy_sha256':self.c.sha(self.policy),'assignment_id':claim['attempt_id'],'run_id':run_id,'base_commit':terms['base_commit'],'base_tree_manifest_sha256':a.BASE,'driver_sha256':self.c.sha(driver_raw),'harness_closure_sha256':policy['harness_closure_sha256'],'provider_model':a.MODEL,'stage_profile_sha256':self.c.sha(profile),'purpose':'funded task development only; ten-stage acceptance plan selected after authored candidate is retained'});rr=a.canonical(request)
  return {'files':{'request':rr,'task_terms':self.terms,'acceptance_profile':self.policy,'plan':plan,'stage_profile':profile,'driver':driver_raw,'source_manifest':base_manifest,'source_bundle':base_bundle},'request_sha256':self.c.sha(p.REQUEST_SCHEMA.encode()+b'\0'+rr),'plan_sha256':self.c.sha(plan),'stage_profile_sha256':self.c.sha(profile),'authority':'Public byte assembly only; independently funded claim and new execution admission required'}
