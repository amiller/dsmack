"""One new upfront substring task. Public byte lowering; no funding or execution.

Reuse the reviewed V2/S0 constructors in a fresh module namespace. Prior cases
and their source bytes remain unchanged; this adapter accepts one exact new case.
"""
from pathlib import Path
import hashlib,json,types
HERE=Path(__file__).resolve().parent
TASK_ID='board-search-opus48-transport-v2-substring-v1'
CASE='substring'
LEGACY_SHA='feaf7aacc9c73684ec34af60e069670ee8e29b3b472d464792beaf97848f47f1'
PINS={'policy':'2c2bd9c494fe9118f6d15e09785ee24c8890ff4a37bafe6cc62eab0ecd93f088','terms':'32f084dfb788a095f7b299639f9c20b8dfc45a6c2aa698011ed0761d40a8e578','qualified_base':'db1696753c370d7fa30d6d766c63beb7743567f1f8d0257eebfb73594ef8a6ad'}
SPEC='da683b597ab8c0764e9a003b85d36203591a48c726ae1927e4b8af1a00ce7b09'
BASE='b44abf143bc7a4c6f3463bdda2c9fceefc8ec7bd63204de0a71ed714bdbbc143'
def need(v,m):
 if not v:raise ValueError(m)
def legacy():
 p=HERE/'transport_v2_inputs.py';b=p.read_bytes();need(hashlib.sha256(b).hexdigest()==LEGACY_SHA,'original V2 host source pin')
 m=types.ModuleType('selected_substring_v2');m.__file__=str(p);exec(compile(b,str(p),'exec'),m.__dict__)
 # This dictionary belongs only to this fresh namespace, never the old module.
 m.IDS={'first':TASK_ID};return m

def validate_selection(raw,expected,documents):
 m=legacy();c=m.load('reference/transport_v2_policy.py');c.digest(expected);need(c.sha(raw)==expected,'external substring selection hash');v=c.parse(raw)
 need(c.canonical(v)==raw and type(v)is dict and set(v)=={'schema','files'}and v['schema']=='dsmack-substring-requester-selection/1','closed substring selection')
 need(type(v['files'])is dict and set(v['files'])==set(PINS)and type(documents)is dict and set(documents)==set(PINS),'three exact public inputs')
 for name,d in v['files'].items():
  need(type(d)is dict and set(d)=={'path','bytes','sha256'}and type(d['path'])is str and Path(d['path']).is_absolute()and type(d['bytes'])is int and 0<d['bytes']<=1048576,'public descriptor')
  b=documents[name];need(type(b)is bytes and len(b)==d['bytes']and c.sha(b)==d['sha256']==PINS[name],'fixed new document pin');need(c.canonical(c.parse(b))==b,'canonical selected document')
 p=c.parse(documents['policy']);t=c.parse(documents['terms']);base=c.parse(documents['qualified_base'])
 need(p['policy_id']==t['id']==TASK_ID and t['checker_sha256']==PINS['policy'],'new subject')
 need(p['images']['base_vm_os_image_hash']==t['image_sha256']==base['base_vm_os_image_hash']==BASE,'qualified unchanged base')
 need(p['specification']==p['development']['profile']['specification']and p['specification']['sha256']==SPEC,'new upfront specification')
 need(c.sha(p['specification']['text'].encode())==SPEC and c.sha(c.canonical(p['development']['profile']))==p['development']['profile_sha256'],'spec/profile bytes')
 need(p['acceptance']['all_required']is True and p['acceptance']['generation_count']==3 and p['acceptance']['browser_ci_count']==6 and p['acceptance']['primary_count']==1,'all ten stages')
 return m,c,v

def read_selection(path,expected):
 m=legacy();c=m.load('reference/transport_v2_policy.py');raw=c.read(path,65536);need(c.sha(raw)==expected,'external substring selection hash');v=c.parse(raw)
 need(type(v)is dict and set(v)=={'schema','files'}and type(v['files'])is dict and set(v['files'])==set(PINS),'closed before reads')
 docs={}
 for name,d in v['files'].items():
  need(type(d)is dict and set(d)=={'path','bytes','sha256'}and type(d['path'])is str and Path(d['path']).is_absolute(),'public descriptor before reads');need(d['sha256']==PINS[name]and type(d['bytes'])is int and 0<d['bytes']<=1048576,'fixed descriptor before reads');docs[name]=c.read(d['path'],1048576)
 validate_selection(raw,expected,docs);return raw,docs

class Selected:
 def __init__(self,raw,expected,documents,case=CASE):
  need(case==CASE,'one new substring case only');self.m,self.c,self.config=validate_selection(raw,expected,documents);self.documents=dict(documents);self.case='first';self.internal='first';self.terms=documents['terms'];self.policy=documents['policy'];self.a=self.m.load('acceptance_inputs.py');self.a.POLICY=PINS['policy'];self.a.TERMS=PINS['terms']
  def identity(which):
   need(type(which)is str and which=='first','one closed internal case');return PINS['terms'],TASK_ID
  self.a.case_identity=identity
 def claim(self,claim):
  need(type(claim)is dict,'actual public claim required');return self.m.Selected.claim(self,claim)
 def develop(self,*args,**kw):return self.m.Selected.develop(self,*args,**kw)
 def plan(self,*args,**kw):return self.m.Selected.plan(self,*args,**kw)
 def assemble(self,*args,**kw):return self.m.Selected.assemble(self,*args,**kw)
