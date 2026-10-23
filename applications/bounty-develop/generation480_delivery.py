#!/usr/bin/env python3
"""Closed paid480 image lowering; reuse reviewed public-only host constructors."""
from pathlib import Path
import hashlib,json,sys,types
HERE=Path(__file__).resolve().parent
TASK='board-search-opus48-transport-v2-paid480-v1'
IMAGE='sha256:d57ab5ad98dca0a2a62a8a0bf84fda4de8ccf6d3f482ddf29606e9ddc800b144'
CONFIG='sha256:a36c147163224aa199dc2ee32e9f7a1a720271faef3973ddf09a9b5070f6c578'
SOURCES={'prepare':'410969ee97e978abd8476e32df7d53f1b73dc6dcb73a778a65536a7ada86b352','build':'ca4dec97c12d0ab0cfa93fde5f54172954e78126acac45bd8bec087b03c90f3a'}
def selected(mode):
 if mode not in SOURCES:raise ValueError('Closed prepare or build operation required')
 path=HERE/(mode+'_generation.py');raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SOURCES[mode]:raise ValueError('Original public constructor changed')
 m=types.ModuleType('selected_paid480_'+mode);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);m.IMAGE=IMAGE
 if mode=='build':m.CONFIG=CONFIG
 else:
  original=m.generation_request
  def generation_request(result,expected_spec):
   original(result,expected_spec);r=result['request'];policy=json.loads(result['input_bytes']['acceptance_profile']);g=policy['acceptance']['judge_generation']
   m.need(r['task_id']==TASK and policy['policy_id']==TASK and policy['images']['generation_oci']==IMAGE,'new paid480 subject/image')
   m.need(g['model_wall_seconds']==480 and g['outer_stage_wall_seconds']==550 and g['native_vm_wall_seconds']==600 and g['max_turns']==2 and g['generator_source_sha256']=='fb157cd427c05f421f094d357773dc275e39c4bb1d12e02363e81dbb47d7592e','new480 source/budgets')
  m.generation_request=generation_request
  configure=m.generation_manifest
  def generation_manifest(*args):
   manifest,slots=configure(*args);m.need(manifest['limits']['timeout_s']==550,'outer550 manifest required');return manifest,slots
  m.generation_manifest=generation_manifest
 return m
if __name__=='__main__':
 try:
  mode=sys.argv.pop(1);selected(mode).main()
 except Exception:raise SystemExit('Paid480 public generation delivery refused; no provider or VM authority.')from None
