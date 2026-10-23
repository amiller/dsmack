// Unsigned pilot projection. This does not verify Apple evidence, sign a verdict,
// prove storage availability, broadcast a transaction, or establish receipt.
import { verify } from 'node:crypto';
import { canonical, sha, exact, need } from '../bounty-demo/core.mjs';
import { validateImageBinding } from './admission-identities.mjs';

const hash = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const address = x => typeof x === 'string' && /^0x[0-9a-f]{40}$/.test(x) && x !== '0x'+'0'.repeat(40);
const uint = x => typeof x === 'string' && /^(0|[1-9][0-9]*)$/.test(x) && BigInt(x)<2n**256n;
function digest(domain, value) { return sha(Buffer.concat([Buffer.from(domain+'\0'),Buffer.from(canonical(value))])); }
function equal(actual, wanted, name) { need(actual===wanted,'binding mismatch: '+name); }
function validateRequest(r){
  for(const k of ['task_id','attempt_id','run_id'])need(typeof r[k]==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(r[k]),'invalid request '+k);
  for(const k of ['task_terms_sha256','attempt_nonce','acceptance_profile_sha256'])need(hash(r[k]),'invalid request '+k);
  exact(r.base,['repo','commit','tree_manifest_sha256']);
  need(typeof r.base.repo==='string'&&/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(r.base.repo)&&/^[a-f0-9]{40}$/.test(r.base.commit)&&hash(r.base.tree_manifest_sha256),'invalid request base');
  exact(r.toolchain,['platform','image_digest']);
  need(r.toolchain.platform==='linux/arm64'&&typeof r.toolchain.image_digest==='string'&&/^sha256:[0-9a-f]{64}$/.test(r.toolchain.image_digest),'invalid request toolchain');
  if(r.run_role==='review'){
    exact(r.candidate,['upstream_commit','tree_manifest_sha256','admission_transform_sha256']);
    need((r.candidate.upstream_commit===null||typeof r.candidate.upstream_commit==='string'&&/^[a-f0-9]{40}$/.test(r.candidate.upstream_commit))&&hash(r.candidate.tree_manifest_sha256)&&hash(r.candidate.admission_transform_sha256),'invalid request candidate');
  }else need(r.run_role==='develop'&&r.candidate===null,'invalid develop request');
  need(Array.isArray(r.required_artifacts)&&r.required_artifacts.length>=1&&r.required_artifacts.length<=32,'invalid required artifacts');
  let previous='';for(const name of r.required_artifacts){need(typeof name==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(name)&&name>previous,'invalid artifact order/name');previous=name;}
}
function document(raw, max=131072) {
  need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=max,'document byte bound');
  const value=JSON.parse(raw.toString('utf8'));
  // Requiring canonical bytes also refuses duplicate JSON keys and alternate encodings.
  need(Buffer.from(canonical(value)).equals(raw),'canonical document required'); return value;
}
export function treeIdentity(raw) {
  const tree=document(raw,4*1024*1024); need(Array.isArray(tree)&&tree.length<=10000,'source manifest required');
  const seen=new Set(); let previous='';
  for(const e of tree){
    exact(e,['path','mode','bytes','sha256']);
    need(typeof e.path==='string'&&e.path.length<=512&&/^[A-Za-z0-9_.@+/-]+$/.test(e.path),'invalid source path');
    const parts=e.path.split('/');
    need(parts.every(p=>p&&p!=='.'&&p!=='..'&&p!=='.git'),'invalid source path');
    need(e.path>previous,'source order/duplicate');
    for(let i=1;i<parts.length;i++)need(!seen.has(parts.slice(0,i).join('/')),'file ancestor conflict');
    need([420,493].includes(e.mode)&&Number.isSafeInteger(e.bytes)&&e.bytes>=0&&hash(e.sha256),'invalid source entry');
    seen.add(e.path);previous=e.path;
  }
  return digest('dsmack-bounty-source-tree/1',tree);
}

// expected is coordinator-admitted immutable context, never a worker HTTP body.
// chain is an independently obtained on-chain snapshot. Callers must separately
// authenticate its RPC/finality and payee acknowledgment before using this plan.
export function project({store,attemptId,expected,requestBytes,reportBytes,deliveryBytes,bundleBytes,candidateManifestBytes,chain}) {
  exact(expected,['request_sha256','run_id','run_role','execution_evidence_sha256','acceptance_results_sha256','chain',...(Object.hasOwn(expected,'image_binding')?['image_binding']:[])]);
  for(const k of ['request_sha256','execution_evidence_sha256','acceptance_results_sha256'])need(hash(expected[k]),'invalid expected '+k);
  const a=store.attempt(attemptId),t=store.task(a.task_id),cert=a.verdict,p=cert?.payload;
  need(a.state==='verified'&&p?.accepted===true,'authenticated accepted attempt required');
  const key=store.verifierKeys[cert.key_id];need(key,'configured verification key required');
  need(verify(null,Buffer.from(canonical(p)),key,Buffer.from(cert.signature,'base64')),'invalid verifier signature');
  // Expiry governs first admission, not the lifetime of already accepted evidence.
  // This server-owned timestamp is never inferred for legacy records or refreshed
  // by retries. Fresh chain/deadline authorization remains a separate signing gate.
  const received=a.verdict_received_at;
  need(Number.isSafeInteger(received)&&received>=a.created_at&&received<=store.now()+30&&
    Number.isSafeInteger(p.issued_at)&&Number.isSafeInteger(p.expires_at)&&p.issued_at>=a.created_at&&
    p.issued_at<=received+30&&p.expires_at>received&&p.expires_at>p.issued_at&&p.expires_at-p.issued_at<=3600,'invalid verdict admission time');
  need(p.checks.apple===true&&p.checks.outputs===true&&p.checks.functional===true,'incomplete verdict');
  for(const [k,v] of Object.entries({task_id:t.id,terms_sha256:t.terms_sha256,attempt_id:a.id,nonce:a.nonce,payee:a.payee,candidate_sha256:a.candidate_sha256,bundle_sha256:a.bundle_sha256,checker_sha256:t.checker_sha256,image_sha256:t.image_sha256,harness_sha256:t.harness_sha256}))equal(p[k],v,k);
  const r=document(requestBytes);
  exact(r,['schema','task_id','task_terms_sha256','attempt_id','attempt_nonce','run_id','run_role','acceptance_profile_sha256','base','candidate','toolchain','required_artifacts']);
  equal(r.schema,'dsmack-bounty-public-request/1','request schema');
  validateRequest(r);
  const requestHash=digest(r.schema,r); equal(requestHash,expected.request_sha256,'request');
  for(const [k,v] of Object.entries({task_id:t.id,task_terms_sha256:t.terms_sha256,attempt_id:a.id,attempt_nonce:a.nonce,run_id:expected.run_id,run_role:expected.run_role,acceptance_profile_sha256:t.checker_sha256}))equal(r[k],v,k);
  equal(r.base.repo,'https://github.com/'+t.repo,'repo');equal(r.base.commit,t.base_commit,'base commit');
  equal(r.toolchain.platform,'linux/arm64','platform');equal(r.toolchain.image_digest,'sha256:'+(Object.hasOwn(expected,'image_binding')?validateImageBinding(expected.image_binding,t):t.image_sha256),'image');
  need(['review','develop'].includes(r.run_role),'run role');
  const candidate=treeIdentity(candidateManifestBytes);equal(candidate,a.candidate_sha256,'actual candidate manifest');
  if(r.run_role==='review')equal(r.candidate?.tree_manifest_sha256,candidate,'review input candidate');
  else equal(r.candidate,null,'develop input candidate');
  need(Buffer.isBuffer(bundleBytes)&&bundleBytes.length>0,'delivered bundle bytes required');
  equal(sha(bundleBytes),a.bundle_sha256,'delivered bundle');
  const report=document(reportBytes);
  exact(report,['schema','request_sha256','task_terms_sha256','acceptance_profile_sha256','attempt_id','attempt_nonce','run_id','run_role','candidate_tree_manifest_sha256','bundle_sha256','execution_evidence_sha256','acceptance_results_sha256','accepted']);
  for(const [k,v] of Object.entries({schema:'dsmack-bounty-acceptance-report/1',request_sha256:requestHash,task_terms_sha256:t.terms_sha256,acceptance_profile_sha256:t.checker_sha256,attempt_id:a.id,attempt_nonce:a.nonce,run_id:r.run_id,run_role:r.run_role,candidate_tree_manifest_sha256:candidate,bundle_sha256:a.bundle_sha256,execution_evidence_sha256:expected.execution_evidence_sha256,acceptance_results_sha256:expected.acceptance_results_sha256,accepted:true}))equal(report[k],v,'report '+k);
  const reportHash=sha(reportBytes);equal(reportHash,p.report_sha256,'signed report');
  const delivery=document(deliveryBytes);
  exact(delivery,['schema','request_sha256','attempt_id','candidate_sha256','bundle_sha256','bundle_bytes','report_sha256']);
  for(const [k,v] of Object.entries({schema:'dsmack-bounty-delivery-manifest/1',request_sha256:requestHash,attempt_id:a.id,candidate_sha256:candidate,bundle_sha256:a.bundle_sha256,bundle_bytes:bundleBytes.length,report_sha256:reportHash}))equal(delivery[k],v,'delivery '+k);
  exact(chain,['chain_id','contract','task_id','assignment_id','assignment_task_id','worker','package_hash','policy_hash','completion_pay_wei','assignment_state']);
  exact(expected.chain,['chain_id','contract','task_id','assignment_id','completion_pay_wei']);
  for(const k of Object.keys(expected.chain))equal(chain[k],expected.chain[k],'admitted chain '+k);
  equal(chain.assignment_task_id,chain.task_id,'assignment parent task');
  need(uint(chain.chain_id)&&BigInt(chain.chain_id)>0n&&uint(chain.task_id)&&BigInt(chain.task_id)>0n&&uint(chain.assignment_id)&&BigInt(chain.assignment_id)>0n&&uint(chain.completion_pay_wei)&&BigInt(chain.completion_pay_wei)>0n,'invalid chain integer');
  need(address(chain.contract)&&address(chain.worker),'invalid chain address');equal(chain.worker,a.payee,'payee/submitter');
  equal(chain.package_hash,'0x'+t.terms_sha256,'offer package');equal(chain.policy_hash,'0x'+t.checker_sha256,'acceptance policy');
  equal(chain.assignment_state,'Reserved','chain assignment state');
  const evidence=digest('dsmack-bounty-settlement-evidence/1',{schema:'dsmack-bounty-settlement-evidence/1',request_sha256:requestHash,report_sha256:reportHash,verdict_sha256:sha(canonical(cert))});
  const message={assignmentId:chain.assignment_id,taskId:chain.task_id,packageHash:chain.package_hash,policyHash:chain.policy_hash,worker:a.payee,candidate:'0x'+candidate,evidence:'0x'+evidence,delivery:'0x'+sha(deliveryBytes),outcome:2,payout:chain.completion_pay_wei};
  return {schema:'dsmack-bounty-unsigned-settlement-proposal/1',authority:'none',payment_received:false,
    submit:{from:a.payee,method:'submit',args:[chain.assignment_id,message.candidate,message.evidence,message.delivery]},
    typed_data:{domain:{name:'DsmackWorkEscrow',version:'2',chainId:chain.chain_id,verifyingContract:chain.contract},primaryType:'Decision',types:{Decision:[['assignmentId','uint256'],['taskId','uint256'],['packageHash','bytes32'],['policyHash','bytes32'],['worker','address'],['candidate','bytes32'],['evidence','bytes32'],['delivery','bytes32'],['outcome','uint8'],['payout','uint256']].map(([name,type])=>({name,type}))},message},
    remaining_gates:['genuine verifier and artifact completeness','authenticated chain snapshot and payee acknowledgment','worker submission and matching stored commitments','independent execution/review/delivery signatures','confirmed resolution credit then withdrawal receipt']};
}
