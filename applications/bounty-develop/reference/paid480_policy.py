#!/usr/bin/env python3
"""Closed prospective paid480 policy derivative. Never funding or execution."""
import argparse,copy,hashlib,json,os,re,stat,subprocess
from pathlib import Path
TASK_ID='board-search-opus48-transport-v2-paid480-v1'
PARENT_IMAGE='d91250b5d024b5b995de52e20eba57ba48f01e9562bec4562d1f88702d2d675c'
GENERATOR='fb157cd427c05f421f094d357773dc275e39c4bb1d12e02363e81dbb47d7592e'
RECIPE='e50310a53eb43a7c5bc90fa48bcb798bd85bc85b260feec4045153a66eaa0963'
OLD_GENERATOR='5285751bb2ca25fb4dd72dfb6e3f0467eba101166b3066a4646a412448f61973'
PINS={'policy':'2c2bd9c494fe9118f6d15e09785ee24c8890ff4a37bafe6cc62eab0ecd93f088','terms':'32f084dfb788a095f7b299639f9c20b8dfc45a6c2aa698011ed0761d40a8e578','harness':'a14b0753e786ed6493546781b6e59096a9d487e115e4d393c685ce9f6200aeca','recipe_closure':'e359510d100901e959b2ac29421bf3bdfa7882053b791c5d42c54fb303b392ca'}
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def parse(b):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate key');d[k]=v
  return d
 def refuse(_):raise ValueError('noninteger JSON')
 return json.loads(b,object_pairs_hook=pairs,parse_float=refuse,parse_constant=refuse)
def digest(v):need(type(v)is str and re.fullmatch('[0-9a-f]{64}',v)and len(set(v))>1,'actual SHA256');return v
def read(p,bound):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=bound,'bounded public file');b=f.read(bound+1);t=os.fstat(f.fileno());need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns)and len(b)==s.st_size,'stable public file');return b

def selected_image(raw,expected):
 digest(expected);need(sha(raw)==expected,'external actual image descriptor pin');v=parse(raw);need(canonical(v)==raw,'canonical image descriptor')
 need(set(v)=={'schema','parent_oci_manifest_sha256','oci_manifest_sha256','oci_config_sha256','generator_source_sha256','changed_files','unchanged_parent_layers_preserved','original_derivation'},'closed image descriptor')
 need(v['schema']=='dsmack-paid480-generator-image/1'and v['parent_oci_manifest_sha256']==PARENT_IMAGE and v['generator_source_sha256']==GENERATOR and v['changed_files']==['opt/bounty-judges/generate.py']and v['unchanged_parent_layers_preserved']is True,'one-file480 derivative')
 for k in ['oci_manifest_sha256','oci_config_sha256']:digest(v[k])
 need(v['oci_manifest_sha256']!=PARENT_IMAGE,'new OCI required');d=v['original_derivation'];need(type(d)is dict and set(d)=={'path','bytes','sha256'}and Path(d['path']).is_absolute()and type(d['bytes'])is int and d['bytes']>0,'original derivation descriptor');digest(d['sha256']);return v

def construct(originals,image_raw,expected_image_sha,generator_raw,recipe_raw):
 need(set(originals)==set(PINS),'closed original public documents');docs={}
 for k,b in originals.items():need(sha(b)==PINS[k],'original '+k+' pin');docs[k]=parse(b);need(canonical(docs[k])==b,'original canonical '+k)
 image=selected_image(image_raw,expected_image_sha);need(sha(generator_raw)==GENERATOR,'paid generator source');need(sha(recipe_raw)==RECIPE,'fixed paid480 recipe source');recipe=parse(recipe_raw);need(canonical(recipe)==recipe_raw,'canonical versioned recipe');need(recipe['version']=='board-search-opus48-declarative-paid480-v1'and recipe['requested_model']=='claude-opus-4-8'and recipe['cli_version']=='2.1.187','paid recipe identity')
 need(recipe['derived_generator_oci_manifest_sha256']==image['oci_manifest_sha256'],'actual OCI in versioned recipe');bounds=recipe['bounds'];need(bounds['model_wall_seconds']==480 and bounds['outer_stage_wall_seconds']==550 and bounds['native_vm_wall_seconds']==600 and bounds['max_turns']==2 and bounds['native_memory_mib']==4096 and bounds['native_vcpus']==1,'coherent480/550/600 recipe')
 selected_recipe=canonical(recipe);closure=copy.deepcopy(docs['recipe_closure']);rows=closure['files'];matches=[r for r in rows if r['path']=='applications/bounty-judges/generate.py'];need(len(matches)==1 and matches[0]['sha256']==OLD_GENERATOR,'original generator closure');matches[0].update(bytes=len(generator_raw),sha256=GENERATOR)
 path='applications/bounty-judges/generation-recipe-paid480.json';need(not any(r['path']==path for r in rows),'fresh recipe version');rows.append({'path':path,'bytes':len(selected_recipe),'sha256':sha(selected_recipe)});rows.sort(key=lambda r:r['path']);closure_raw=canonical(closure)
 harness=copy.deepcopy(docs['harness']);need(harness['oci']['generation_oci']=='sha256:'+PARENT_IMAGE,'original generator image');harness['oci']['generation_oci']='sha256:'+image['oci_manifest_sha256'];harness['recipe_source_closure_sha256']=sha(closure_raw);harness_raw=canonical(harness)
 p=copy.deepcopy(docs['policy']);need(p['acceptance']['judge_generation']['model_wall_seconds']==180 and p['resources']['runtime_seconds']==600,'original budget');p['policy_id']=TASK_ID;p['images']['generation_oci']=harness['oci']['generation_oci'];p['harness_closure_sha256']=sha(harness_raw);p['recipe_closure_sha256']=sha(closure_raw)
 g=p['acceptance']['judge_generation'];g.update(model_wall_seconds=480,outer_stage_wall_seconds=550,native_vm_wall_seconds=600,generator_source_sha256=GENERATOR,recipe_source_sha256=sha(selected_recipe),recipe_note='Selected versioned paid480 recipe and actual one-file OCI bind480 model/550 child/600 native bounds; old180 recipe remains historical, never runtime authority.')
 need(p['acceptance']['all_required']is True and p['acceptance']['generation_count']==3 and p['acceptance']['browser_ci_count']==6 and p['acceptance']['primary_count']==1 and p['acceptance']['primary']['no_skip_retry_or_infrastructure_success']is True,'unchanged full acceptance');policy=canonical(p)
 t=copy.deepcopy(docs['terms']);t.update(id=TASK_ID,title='[board] Search cards — upfront480s Opus4.8 fresh paid turn',checker_sha256=sha(policy),harness_sha256=sha(harness_raw));terms=canonical(t)
 return {'acceptance-policy.json':policy,'task-terms.json':terms,'HARNESS-CLOSURE.json':harness_raw,'RECIPE-SOURCE-CLOSURE.json':closure_raw,'generation-recipe-paid480.json':selected_recipe}

def main():
 ap=argparse.ArgumentParser()
 for k in ['policy','terms','harness','recipe-closure','image-descriptor','expected-image-descriptor-sha256','generator-source','recipe','node','out']:ap.add_argument('--'+k,required=True)
 a=ap.parse_args();originals={k:read(getattr(a,k),1048576)for k in ['policy','terms','harness']};originals['recipe_closure']=read(a.recipe_closure,1048576);outputs=construct(originals,read(a.image_descriptor,65536),a.expected_image_descriptor_sha256,read(a.generator_source,65536),read(a.recipe,65536));need(Path(a.node).is_absolute(),'explicit host Node');program="const fs=require('node:fs');const v=JSON.parse(fs.readFileSync(0,'utf8'));const c=x=>Array.isArray(x)?x.map(c):x!==null&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,c(x[k])])):x;process.stdout.write(JSON.stringify(c(v)));"
 for raw in outputs.values():
  checked=subprocess.run([a.node,'-e',program],input=raw,capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin'});need(checked.returncode==0 and checked.stdout==raw,'Node canonical parity')
 out=Path(a.out);need(out.is_absolute(),'absolute output');out.mkdir(mode=0o700)
 for n,b in outputs.items():
  fd=os.open(out/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 print(json.dumps({'task_id':TASK_ID,'files':{n:{'bytes':len(b),'sha256':sha(b)}for n,b in outputs.items()},'scope':'prospective public documents only; no funding, claim, provider or VM authority'},sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit('Paid480 public policy preparation refused; preserve partial output.')from None
