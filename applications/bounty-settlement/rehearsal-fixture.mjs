// SYNTHETIC fixture only. No genuine Apple/provider evidence.
import { generateKeyPairSync, sign } from 'node:crypto';
import { Store, canonical, sha } from '../bounty-demo/core.mjs';
import { treeIdentity } from './projection.mjs';
const bytes=x=>Buffer.from(canonical(x)),h='a'.repeat(64);
export function syntheticFixture(role='review',payee='0x'+'2'.repeat(40)){
  const keys=generateKeyPairSync('ed25519');
  const store=new Store(':memory:',{now:()=>1000,verifierKeys:{fixture:keys.publicKey.export({type:'spki',format:'pem'})}});
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
  store.verdict(a.id,{payload,signature:sign(null,bytes(payload),keys.privateKey).toString('base64'),key_id:'fixture'});
  const deliveryBytes=bytes({schema:'dsmack-bounty-delivery-manifest/1',request_sha256,attempt_id:a.id,candidate_sha256:candidate,bundle_sha256:sha(bundleBytes),bundle_bytes:bundleBytes.length,report_sha256:sha(reportBytes)});
  const chain={chain_id:'31337',contract:'0x'+'3'.repeat(40),task_id:'1',assignment_id:'2',assignment_task_id:'1',worker:payee,package_hash:'0x'+t.terms_sha256,policy_hash:'0x'+h,completion_pay_wei:'1000000000000000000',assignment_state:'Reserved'};
  expected.chain=Object.fromEntries(['chain_id','contract','task_id','assignment_id','completion_pay_wei'].map(k=>[k,chain[k]]));
  return {store,attemptId:a.id,expected,requestBytes,reportBytes,deliveryBytes,bundleBytes,candidateManifestBytes,chain};
}
