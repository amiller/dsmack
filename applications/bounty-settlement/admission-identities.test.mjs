// Synthetic /2 graph controls; never Apple or financial qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { syntheticAdapterFixture as fixture } from './adapter-fixture.mjs';
import { AcceptanceAdapter } from './acceptance-adapter.mjs';
import { validateReceiptRunId, validateReceiptPolicy, D9_BASE, B44_BASE, D9_RECEIPT_POLICY, B44_RECEIPT_POLICY } from './admission-identities.mjs';
const withModern=fn=>{const f=fixture({modernAdmission:true,bundledOutputs:true});try{return fn(f);}finally{f.store.close();}};
test('version2 full ten-stage graph separates semantic harness, base VM, OCI and receipt producer ID',()=>withModern(f=>{const result=new AcceptanceAdapter(f).evaluate(f.attemptId,f.input);assert.equal(result.expected.image_binding.base_vm_os_image_sha256,D9_BASE);assert.notEqual(result.expected.image_binding.primary_oci_manifest_sha256,D9_BASE);}));
test('version2 independently held mappings reject substitutions',()=>{
 for(const mode of ['base','launch-base','OCI','closure','recipe','driver-path','driver-bytes','producer-policy','unknown-schema'])withModern(f=>{
  const a=f.admissions[f.attemptId],s=a.stages[0];
  if(mode==='base')s.native.base_vm.os_image_hash='0'.repeat(64);
  if(mode==='launch-base')s.native.base_vm_launch.admission.os_image_hash='0'.repeat(64);
  if(mode==='OCI')a.expected.stages[9].oci_manifest_sha256='0'.repeat(64);
  if(mode==='closure')a.harness_binding.harness_closure_b64=Buffer.from('{}').toString('base64');
  if(mode==='recipe')a.harness_binding.recipe_source_closure_b64=Buffer.from('{}').toString('base64');
  if(mode==='driver-path')a.harness_binding.driver_source_paths.base='applications/bounty-develop/driver.py';
  if(mode==='driver-bytes')s.driver_sha256='0'.repeat(64);
  if(mode==='producer-policy')s.native.receipt_run_id_policy.mode='any-receipt';
  if(mode==='unknown-schema')a.schema='dsmack-bounty-acceptance-admission/3';
  assert.throws(()=>new AcceptanceAdapter(f).evaluate(f.attemptId,f.input),undefined,mode);
 });
});
test('producer grammar binds selector and bounded canonical positive PID',()=>withModern(f=>{
 const a=f.admissions[f.attemptId],s=a.stages[0],pin=a.expected.stages[0],o=f.input.originals[0],m=JSON.parse(o.manifestBytes),subject=s.context.subject;
 for(const run_id of ['guest-other-1','guest-base-1-0','guest-base-1-01','guest-base-1--1','guest-base-1-4194305','guest-base-1-1x',pin.run_id])assert.throws(()=>validateReceiptRunId({run_id},m,subject,pin,s.native));
 assert.equal(validateReceiptRunId({run_id:'guest-base-1-4194304'},m,subject,pin,s.native),'guest-base-1-4194304');
 assert.throws(()=>validateReceiptRunId({run_id:'guest-base-1-1'},{...m,name:'other'},subject,pin,s.native));
}));
test('legacy admission retains exact native run ID and OCI task semantics',()=>{const f=fixture();try{new AcceptanceAdapter(f).evaluate(f.attemptId,f.input);const a=f.admissions[f.attemptId];a.expected.stages[9].oci_manifest_sha256=D9_BASE;assert.throws(()=>new AcceptanceAdapter(f));}finally{f.store.close();}});
test('modern signed measured request still rejects assignment nonce substitution',()=>withModern(f=>{
 const o=f.input.originals.find(x=>x.stage_id==='primary-review');const e=JSON.parse(o.publicInputsBytes);const row=e.files.find(x=>x.slot==='stage-request');const r=JSON.parse(Buffer.from(row.content_base64,'base64'));r.attempt_nonce='0'.repeat(64);row.content_base64=Buffer.from(JSON.stringify(r)).toString('base64');o.publicInputsBytes=Buffer.from(JSON.stringify(e));assert.throws(()=>new AcceptanceAdapter(f).evaluate(f.attemptId,f.input));
}));

test('explicit B44 producer policy passes complete modern ten-stage graph',()=>{
 const f=fixture({modernAdmission:true,bundledOutputs:true,modernBase:B44_BASE});
 try{const value=new AcceptanceAdapter(f).evaluate(f.attemptId,f.input);assert.equal(value.expected.image_binding.base_vm_os_image_sha256,B44_BASE);assert.equal(f.result.stages.length,10);}finally{f.store.close();}
});
test('producer policies refuse crossed modes, arbitrary bases and manifest substitution',()=>{
 const native=base=>({base_vm:{os_image_hash:base},base_vm_launch:{admission:{os_image_hash:base}}});
 for(const [policy,base]of[[D9_RECEIPT_POLICY,D9_BASE],[B44_RECEIPT_POLICY,B44_BASE]]){
  assert.equal(validateReceiptPolicy(policy,native(base)),base);
  for(const wrong of [base===D9_BASE?B44_BASE:D9_BASE,'0'.repeat(64)])assert.throws(()=>validateReceiptPolicy(policy,native(wrong)));
  assert.throws(()=>validateReceiptPolicy({...policy,mode:'guest-selector-pid'},native(base)));
  assert.throws(()=>validateReceiptPolicy({...policy,schema:'dsmack-native-receipt-run-id/2'},native(base)));
  const n={...native(base),receipt_run_id_policy:policy},subject={receipt_selector:'fixed-selector'},pin={run_id:'planned-native-id'};
  assert.equal(validateReceiptRunId({run_id:'guest-fixed-selector-1'},{name:'fixed-selector',base_vm:{os_image_hash:base}},subject,pin,n),'guest-fixed-selector-1');
  assert.throws(()=>validateReceiptRunId({run_id:'guest-fixed-selector-1'},{name:'fixed-selector',base_vm:{os_image_hash:'0'.repeat(64)}},subject,pin,n));
  for(const run_id of ['guest-other-1','guest-fixed-selector-0','guest-fixed-selector-01','guest-fixed-selector-4194305',pin.run_id])assert.throws(()=>validateReceiptRunId({run_id},{name:'fixed-selector',base_vm:{os_image_hash:base}},subject,pin,n));
 }
});
