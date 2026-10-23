#!/usr/bin/env python3
"""Closed paid480 image lowering; reuse reviewed public-only host constructors."""
from pathlib import Path
import hashlib,json,sys,types
HERE=Path(__file__).resolve().parent
TASK='board-search-opus48-transport-v2-paid480-serialization-v1'
IMAGE='sha256:74b7aeff23ffc3780d054004eafedaecd005dcd983d3285f2a5d082d75028082'
CONFIG='sha256:c7b4447c04bb07ae7c61a1d879c480e87d6b7d4879d10f3d811dc6012def6b0f'
SERIALIZATION={'authorship': 'Raw bytes are model-emitted; canonical suite bytes and the serialization record are deterministic measured-runtime outputs, not model-authored byte claims.', 'bounds': 'Both raw and canonical suite bytes must independently be 1..262144; duplicate keys, floats, nonfinite values, unsafe/noncanonical integers and invalid Unicode are refused. Arrays/actions/IDs/text values are unchanged; deterministic JSON encoding may change whitespace, object key order and equivalent escape spellings only; no Unicode normalization.', 'canonical_artifact': 'suite.json', 'host_recompute': 'Re-run the pinned original model observer over authenticated transcript.jsonl; its exact raw result bytes must equal suite-model-raw.txt. Re-run pinned generator canonicalize_suite(raw), require byte equality with suite.json, and require canonical suite_serialization_record(raw,suite) byte equality with suite-serialization.json. Then apply the unchanged strict Node suite contract and compare its returned bytes exactly. Keep the original CLI/model, prompt/snapshot, commitment, outcome and resource checks. No content repair, extra model call or judge retry.', 'raw_artifact': 'suite-model-raw.txt', 'record_artifact': 'suite-serialization.json', 'schema': 'dsmack-bounty-suite-serialization/1', 'version': 'strict-json-canonical-suite/1'}
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
   m.need(g.get('serialization')==SERIALIZATION,'exact measured serialization contract')
   m.need(g['model_wall_seconds']==480 and g['outer_stage_wall_seconds']==550 and g['native_vm_wall_seconds']==600 and g['max_turns']==2 and g['generator_source_sha256']=='e761cf4509069c4c6f4ffe545ea7a1546b4f5bd87dee03671e3434370f5886b7','new480 source/budgets')
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
