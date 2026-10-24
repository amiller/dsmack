// Synthetic signatures and bytes: tests never establish genuine Apple acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store, canonical, sha } from '../bounty-demo/core.mjs';
import { project, treeIdentity } from './projection.mjs';
const bytes=x=>Buffer.from(canonical(x)),h='a'.repeat(64),payee='0x'+'2'.repeat(40);
function fixture(role='review',dbPath=':memory:',admit=true){
  const keys=generateKeyPairSync('ed25519');
  const store=new Store(dbPath,{now:()=>1000,verifierKeys:{fixture:keys.publicKey.export({type:'spki',format:'pem'})}});
  const t=store.createTask({id:'board-search',repo:'amiller/bounty-arcade',issue_number:1,title:'SYNTHETIC',base_commit:'b'.repeat(40),checker_sha256:h,image_sha256:h,harness_sha256:h,reward:{amount:'1',asset:'ETH',chain:'local Anvil'}});
  const {attempt:a}=store.claim(t.id,{worker:'distinct Mac operator, not payee',payee});
  const candidateManifestBytes=bytes([{path:'app.js',mode:420,bytes:3,sha256:sha('abc')}]);
  const candidate=treeIdentity(candidateManifestBytes),bundleBytes=Buffer.from('SYNTHETIC bundle, not Apple evidence');
  store.submit(a.id,{candidate_sha256:candidate,bundle_sha256:sha(bundleBytes)});
  const r={schema:'dsmack-bounty-public-request/1',task_id:t.id,task_terms_sha256:t.terms_sha256,attempt_id:a.id,attempt_nonce:a.nonce,run_id:'synthetic-run-1',run_role:role,acceptance_profile_sha256:h,base:{repo:'https://github.com/'+t.repo,commit:t.base_commit,tree_manifest_sha256:h},candidate:role==='review'?{upstream_commit:null,tree_manifest_sha256:candidate,admission_transform_sha256:h}:null,toolchain:{platform:'linux/arm64',image_digest:'sha256:'+h},required_artifacts:['source-bundle']};
  const requestBytes=bytes(r),request_sha256=sha(Buffer.concat([Buffer.from(r.schema+'\0'),requestBytes]));
  const expected={request_sha256,run_id:r.run_id,run_role:role,execution_evidence_sha256:h,acceptance_results_sha256:h};
  const reportBytes=bytes({schema:'dsmack-bounty-acceptance-report/1',request_sha256,task_terms_sha256:t.terms_sha256,acceptance_profile_sha256:h,attempt_id:a.id,attempt_nonce:a.nonce,run_id:r.run_id,run_role:role,candidate_tree_manifest_sha256:candidate,bundle_sha256:sha(bundleBytes),execution_evidence_sha256:h,acceptance_results_sha256:h,accepted:true});
  const payload={schema:'dsmack-bounty-verdict/1',task_id:t.id,terms_sha256:t.terms_sha256,attempt_id:a.id,nonce:a.nonce,payee,candidate_sha256:candidate,bundle_sha256:sha(bundleBytes),checker_sha256:h,image_sha256:h,harness_sha256:h,report_sha256:sha(reportBytes),accepted:true,checks:{apple:true,outputs:true,functional:true},issued_at:1000,expires_at:1200};
  const certificate={payload,signature:sign(null,bytes(payload),keys.privateKey).toString('base64'),key_id:'fixture'};
  if(admit)store.verdict(a.id,certificate);
  const deliveryBytes=bytes({schema:'dsmack-bounty-delivery-manifest/1',request_sha256,attempt_id:a.id,candidate_sha256:candidate,bundle_sha256:sha(bundleBytes),bundle_bytes:bundleBytes.length,report_sha256:sha(reportBytes)});
  const chain={chain_id:'31337',contract:'0x'+'3'.repeat(40),task_id:'1',assignment_id:'2',assignment_task_id:'1',worker:payee,package_hash:'0x'+t.terms_sha256,policy_hash:'0x'+h,completion_pay_wei:'1000000000000000000',assignment_state:'Reserved'};
  expected.chain=Object.fromEntries(['chain_id','contract','task_id','assignment_id','completion_pay_wei'].map(k=>[k,chain[k]]));
  return {store,attemptId:a.id,expected,requestBytes,reportBytes,deliveryBytes,bundleBytes,candidateManifestBytes,chain,certificate};
}
test('M1 exact commitments round-trip into unsigned v2 proposal, not paid state',()=>{
  const f=fixture();try{const p=project(f);assert.equal(p.authority,'none');assert.equal(p.payment_received,false);assert.equal(p.submit.from,payee);assert.equal(p.typed_data.domain.version,'2');assert.equal(p.typed_data.message.candidate,'0x'+treeIdentity(f.candidateManifestBytes));assert.equal(p.typed_data.message.delivery,'0x'+sha(f.deliveryBytes));assert.equal(p.typed_data.message.packageHash,f.chain.package_hash);}finally{f.store.close();}
});
test('M2 distinct operator cannot replace payee as escrow submitter',()=>{const f=fixture();try{assert.throws(()=>project({...f,chain:{...f.chain,worker:'0x'+'4'.repeat(40)}}),/payee/);}finally{f.store.close();}});
test('M3 substitution of request, candidate, bundle, report, delivery or policy refuses',()=>{
  const f=fixture();try{
    for(const field of ['requestBytes','reportBytes','deliveryBytes'])assert.throws(()=>project({...f,[field]:Buffer.from('{}')}));
    assert.throws(()=>project({...f,bundleBytes:Buffer.from('substituted')}),/bundle/);
    assert.throws(()=>project({...f,candidateManifestBytes:bytes([{path:'app.js',mode:420,bytes:3,sha256:h}])}),/candidate/);
    assert.throws(()=>project({...f,chain:{...f.chain,policy_hash:'0x'+'d'.repeat(64)}}),/policy/);
    assert.throws(()=>project({...f,expected:{...f.expected,run_id:'other'}}),/run_id/);
    for(const [key,value] of Object.entries({chain_id:'8453',contract:'0x'+'9'.repeat(40),task_id:'3',assignment_id:'9',completion_pay_wei:'2'}))assert.throws(()=>project({...f,chain:{...f.chain,[key]:value}}),/admitted chain/);
    assert.throws(()=>project({...f,chain:{...f.chain,assignment_task_id:'9'}}),/parent task/);
  }finally{f.store.close();}
});
test('even pinned requests must satisfy nested S0 schema',()=>{
  const f=fixture();try{
    const original=JSON.parse(f.requestBytes);
    for(const change of [r=>r.base.extra='x',r=>r.candidate.admission_transform_sha256='x',r=>r.required_artifacts=['z','a'],r=>r.required_artifacts=['a','a'],r=>r.toolchain.extra='x']){
      const r=structuredClone(original);change(r);const raw=bytes(r);
      const expected={...f.expected,request_sha256:sha(Buffer.concat([Buffer.from(r.schema+'\0'),raw]))};
      assert.throws(()=>project({...f,requestBytes:raw,expected}));
    }
  }finally{f.store.close();}
});
test('M4 develop binds final output despite null input candidate',()=>{const f=fixture('develop');try{assert.equal(project(f).typed_data.message.candidate,'0x'+treeIdentity(f.candidateManifestBytes));}finally{f.store.close();}});
test('accepted evidence survives certificate expiry without changing settlement commitments',()=>{
  const f=fixture();try{const before=project(f);f.store.now=()=>1300;assert.deepEqual(project(f),before);const a=f.store.attempt(f.attemptId);assert.equal(a.verdict_received_at,1000);assert.equal(f.store.verdict(a.id,a.verdict).verdict_received_at,1000);}finally{f.store.close();}
});
test('missing or inconsistent stored admission time cannot rescue a verdict',()=>{
  for(const time of [undefined,999,1100,1200,1300]){const f=fixture();try{const a=f.store.attempt(f.attemptId);if(time===undefined)delete a.verdict_received_at;else a.verdict_received_at=time;f.store.saveAttempt(a);assert.throws(()=>project(f),/admission time/);}finally{f.store.close();}}
});
test('admission survives database reopen; replay cannot refresh it or swap verdict',()=>{
  const directory=mkdtempSync(join(tmpdir(),'bounty-admission-')),file=join(directory,'state.sqlite');let reopened;
  const f=fixture('review',file);try{
    const before=project(f),publicKey=f.store.verifierKeys.fixture.export({type:'spki',format:'pem'});f.store.close();
    reopened=new Store(file,{now:()=>1300,verifierKeys:{fixture:publicKey}});
    assert.deepEqual(project({...f,store:reopened}),before);
    assert.equal(reopened.verdict(f.attemptId,f.certificate).verdict_received_at,1000);
    const changed=structuredClone(f.certificate);changed.payload.report_sha256='f'.repeat(64);
    assert.throws(()=>reopened.verdict(f.attemptId,changed));
    assert.equal(reopened.attempt(f.attemptId).verdict_received_at,1000);
  }finally{reopened?.close();rmSync(directory,{recursive:true,force:true});}
});
test('expired first consumption remains refused and stores no admission time',()=>{
  const f=fixture('review',':memory:',false);try{f.store.now=()=>1300;assert.throws(()=>f.store.verdict(f.attemptId,f.certificate),/stale verdict/);const a=f.store.attempt(f.attemptId);assert.equal(a.state,'submitted');assert.equal(Object.hasOwn(a,'verdict_received_at'),false);}finally{f.store.close();}
});
test('one admission clock sample cannot cross expiry between validation and persistence',()=>{
  const f=fixture('review',':memory:',false);try{
    let calls=0;f.store.now=()=>[1000,1199,1200][Math.min(calls++,2)];
    const a=f.store.verdict(f.attemptId,f.certificate);assert.equal(calls,1);assert.equal(a.verdict_received_at,1000);
    f.store.now=()=>1300;assert.equal(project(f).authority,'none');
  }finally{f.store.close();}
});
test('canonical manifest rejects duplicates, traversal, file ancestors and alternative encoding',()=>{
  const e={path:'a',mode:420,bytes:0,sha256:h};
  for(const m of [[e,e],[{...e,path:'../a'}],[e,{...e,path:'a/b'}],[{...e,path:'.'}]])assert.throws(()=>treeIdentity(bytes(m)));
  assert.throws(()=>treeIdentity(Buffer.from(JSON.stringify([e],null,2))),/canonical/);
});
test('identities equal independently reviewed S0 golden fixture',()=>{
  const f=JSON.parse(readFileSync(new URL('../bounty-recipes/protocol.synthetic.json',import.meta.url)));
  assert.equal(treeIdentity(bytes(f.tree_manifest)),f.tree_manifest_sha256);
  assert.equal(sha(Buffer.concat([Buffer.from(f.request.schema+'\0'),bytes(f.request)])),f.request_sha256);
});
