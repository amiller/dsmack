"""One new upfront guided paid480 task. Public byte lowering; no funding or execution.

Reuse the reviewed V2/S0 constructors in a fresh module namespace. Prior cases
and their source bytes remain unchanged; this adapter accepts one exact new case.
"""
from pathlib import Path
import hashlib,json,types
HERE=Path(__file__).resolve().parent
TASK_ID='board-search-opus48-transport-v2-paid480-serialization-v1'
CASE='serialization-paid480'
LEGACY_SHA='feaf7aacc9c73684ec34af60e069670ee8e29b3b472d464792beaf97848f47f1'
PINS={'policy':'a28aa5b7e13dc3b959da93863a51d8b89b05de302011aed92004dc6485ff8315','terms':'695378e8451b3703b1052f7762023d7c1a99d0c0abff9aea7395a7cf29e75a84','qualified_base':'db1696753c370d7fa30d6d766c63beb7743567f1f8d0257eebfb73594ef8a6ad'}
SPEC='da683b597ab8c0764e9a003b85d36203591a48c726ae1927e4b8af1a00ce7b09'
DEV_SPEC='cf53dd615385dcdfbb62be70a236c0997c372fc30e5d32e20ae291070023b036'
DEV_PROFILE='17098251c88d224c69f037c9c8cdb7dad84d1c60bbbd64e0675ea628c38f9c2c'
SERIALIZATION={'authorship': 'Raw bytes are model-emitted; canonical suite bytes and the serialization record are deterministic measured-runtime outputs, not model-authored byte claims.', 'bounds': 'Both raw and canonical suite bytes must independently be 1..262144; duplicate keys, floats, nonfinite values, unsafe/noncanonical integers and invalid Unicode are refused. Arrays/actions/IDs/text values are unchanged; deterministic JSON encoding may change whitespace, object key order and equivalent escape spellings only; no Unicode normalization.', 'canonical_artifact': 'suite.json', 'host_recompute': 'Re-run the pinned original model observer over authenticated transcript.jsonl; its exact raw result bytes must equal suite-model-raw.txt. Re-run pinned generator canonicalize_suite(raw), require byte equality with suite.json, and require canonical suite_serialization_record(raw,suite) byte equality with suite-serialization.json. Then apply the unchanged strict Node suite contract and compare its returned bytes exactly. Keep the original CLI/model, prompt/snapshot, commitment, outcome and resource checks. No content repair, extra model call or judge retry.', 'raw_artifact': 'suite-model-raw.txt', 'record_artifact': 'suite-serialization.json', 'schema': 'dsmack-bounty-suite-serialization/1', 'version': 'strict-json-canonical-suite/1'}
BASE='b44abf143bc7a4c6f3463bdda2c9fceefc8ec7bd63204de0a71ed714bdbbc143'
def need(v,m):
 if not v:raise ValueError(m)
def legacy():
 p=HERE/'transport_v2_inputs.py';b=p.read_bytes();need(hashlib.sha256(b).hexdigest()==LEGACY_SHA,'original V2 host source pin')
 m=types.ModuleType('selected_serialization_paid480_v2');m.__file__=str(p);exec(compile(b,str(p),'exec'),m.__dict__)
 # This dictionary belongs only to this fresh namespace, never the old module.
 m.IDS={'first':TASK_ID};return m

def validate_selection(raw,expected,documents):
 m=legacy();c=m.load('reference/transport_v2_policy.py');c.digest(expected);need(c.sha(raw)==expected,'external paid480 selection hash');v=c.parse(raw)
 need(c.canonical(v)==raw and type(v)is dict and set(v)=={'schema','files'}and v['schema']=='dsmack-serialization-paid480-requester-selection/1','closed paid480 selection')
 need(type(v['files'])is dict and set(v['files'])==set(PINS)and type(documents)is dict and set(documents)==set(PINS),'three exact public inputs')
 for name,d in v['files'].items():
  need(type(d)is dict and set(d)=={'path','bytes','sha256'}and type(d['path'])is str and Path(d['path']).is_absolute()and type(d['bytes'])is int and 0<d['bytes']<=1048576,'public descriptor')
  b=documents[name];need(type(b)is bytes and len(b)==d['bytes']and c.sha(b)==d['sha256']==PINS[name],'fixed new document pin');need(c.canonical(c.parse(b))==b,'canonical selected document')
 p=c.parse(documents['policy']);t=c.parse(documents['terms']);base=c.parse(documents['qualified_base'])
 need(p['policy_id']==t['id']==TASK_ID and t['checker_sha256']==PINS['policy'],'new subject')
 need(p['images']['base_vm_os_image_hash']==t['image_sha256']==base['base_vm_os_image_hash']==BASE,'qualified unchanged base')
 need(p['specification']['sha256']==SPEC,'unchanged global judge specification')
 dev=p['development']['profile']['specification']
 need(dev['sha256']==DEV_SPEC and c.sha(dev['text'].encode())==DEV_SPEC,'exact upfront DEV guidance')
 need(dev['text'].startswith(p['specification']['text']) and len(dev['text'])>len(p['specification']['text']),'guidance extends unchanged global goal')
 need(p['development']['profile_sha256']==DEV_PROFILE,'exact guided DEV profile')
 need(c.sha(p['specification']['text'].encode())==SPEC and c.sha(c.canonical(p['development']['profile']))==p['development']['profile_sha256'],'spec/profile bytes')
 g=p['acceptance']['judge_generation'];need(g.get('serialization')==SERIALIZATION,'exact measured serialization contract');need(g['model_wall_seconds']==480 and g['outer_stage_wall_seconds']==550 and g['native_vm_wall_seconds']==600 and g['max_turns']==2 and g['generator_source_sha256']=='e761cf4509069c4c6f4ffe545ea7a1546b4f5bd87dee03671e3434370f5886b7'and 'infrastructure_retry_policy'not in g,'fixed paid480 budget/source without retries')
 need(p['images']['generation_oci']=='sha256:74b7aeff23ffc3780d054004eafedaecd005dcd983d3285f2a5d082d75028082'and p['resources']['runtime_seconds']==600,'actual new OCI/native600')
 need(p['acceptance']['all_required']is True and p['acceptance']['generation_count']==3 and p['acceptance']['browser_ci_count']==6 and p['acceptance']['primary_count']==1,'all ten stages')
 return m,c,v

def read_selection(path,expected):
 m=legacy();c=m.load('reference/transport_v2_policy.py');raw=c.read(path,65536);need(c.sha(raw)==expected,'external paid480 selection hash');v=c.parse(raw)
 need(type(v)is dict and set(v)=={'schema','files'}and type(v['files'])is dict and set(v['files'])==set(PINS),'closed before reads')
 docs={}
 for name,d in v['files'].items():
  need(type(d)is dict and set(d)=={'path','bytes','sha256'}and type(d['path'])is str and Path(d['path']).is_absolute(),'public descriptor before reads');need(d['sha256']==PINS[name]and type(d['bytes'])is int and 0<d['bytes']<=1048576,'fixed descriptor before reads');docs[name]=c.read(d['path'],1048576)
 validate_selection(raw,expected,docs);return raw,docs

class Selected:
 def __init__(self,raw,expected,documents,case=CASE):
  need(case==CASE,'one new paid480 case only');self.m,self.c,self.config=validate_selection(raw,expected,documents);self.documents=dict(documents);self.case='first';self.internal='first';self.terms=documents['terms'];self.policy=documents['policy'];self.a=self.m.load('acceptance_inputs.py');self.a.POLICY=PINS['policy'];self.a.TERMS=PINS['terms'];self.a.GEN='74b7aeff23ffc3780d054004eafedaecd005dcd983d3285f2a5d082d75028082'
  def identity(which):
   need(type(which)is str and which=='first','one closed internal case');return PINS['terms'],TASK_ID
  self.a.case_identity=identity
 def claim(self,claim):
  need(type(claim)is dict,'actual public claim required');return self.m.Selected.claim(self,claim)
 def develop(self,*args,**kw):return self.m.Selected.develop(self,*args,**kw)
 def plan(self,*args,**kw):return self.m.Selected.plan(self,*args,**kw)
 def assemble(self,*args,**kw):return self.m.Selected.assemble(self,*args,**kw)
