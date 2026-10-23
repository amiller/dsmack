// Trusted application join. No signing, VM execution, operator replay or funds.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, openSync, closeSync, writeFileSync, rmSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical, sha, exact, need } from '../bounty-demo/core.mjs';
import { encoded, hash, same, document, reportKey, validateContext, verifyOriginalStage, receiptDocument } from './original-report.mjs';
import { verifySourceDelivery } from './source-delivery.mjs';
import { validateOutputBundle } from './output-bundle.mjs';
import { verifySourceRelation } from './source-relation.mjs';
import { validateInputSelection, authenticateMeasuredInputs } from './measured-inputs.mjs';
import { ADMISSION2, validateReceiptPolicy, taskImageBinding, validateHarnessBinding } from './admission-identities.mjs';

const STAGES=['base-1','base-2','base-3','candidate-1','candidate-2','candidate-3','generate-1','generate-2','generate-3','primary-review'];
const PINS=['stage_id','role','judge_index','run_id','request_sha256','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256'];
const taskKeys=['task_id','terms_sha256','checker_sha256','image_sha256','harness_sha256','attempt_id','nonce','payee','candidate_sha256','bundle_sha256'];
const expectedKeys=['plan_sha256','primary_request_sha256','task_terms_sha256','attempt_id','attempt_nonce','base_tree_sha256','candidate_tree_sha256','requested_model','stages'];
const joinPath=fileURLToPath(new URL('./join-original.py',import.meta.url));
function snapshot(store,id){const a=store.attempt(id),t=store.task(a.task_id);return {task_id:t.id,terms_sha256:t.terms_sha256,checker_sha256:t.checker_sha256,image_sha256:t.image_sha256,harness_sha256:t.harness_sha256,attempt_id:a.id,nonce:a.nonce,payee:a.payee,candidate_sha256:a.candidate_sha256,bundle_sha256:a.bundle_sha256};}
function validateAdmission(v) {
  const modern=Object.hasOwn(v,'schema');
  exact(v,modern?['schema','task_image_semantics','harness_binding','task','expected','stages','delivery']:['task','expected','stages','delivery']);
  if(modern){same(v.schema,ADMISSION2,'admission schema');same(v.task_image_semantics,'base-vm-os-image','task image semantics');}
  exact(v.task,taskKeys);exact(v.expected,expectedKeys);
  for(const k of taskKeys.filter(k=>k.endsWith('_sha256')||k==='nonce'))need(hash(v.task[k]),'invalid admitted task '+k);
  for(const k of expectedKeys.filter(k=>k.endsWith('_sha256')))need(hash(v.expected[k]),'invalid admitted expected '+k);
  need(typeof v.expected.requested_model==='string'&&v.expected.requested_model.length>0&&v.expected.requested_model.length<=128,'admitted model required');
  need(Array.isArray(v.expected.stages)&&Array.isArray(v.stages),'admitted stage lists required');
  same(v.expected.stages.map(s=>s.stage_id),STAGES,'closed admitted stage pins');same(v.stages.map(s=>s.stage_id),STAGES,'closed admitted stage contexts');
  same(v.expected.task_terms_sha256,v.task.terms_sha256,'admitted task terms');same(v.expected.attempt_id,v.task.attempt_id,'admitted attempt');
  same(v.expected.attempt_nonce,v.task.nonce,'admitted nonce');same(v.expected.candidate_tree_sha256,v.task.candidate_sha256,'admitted candidate');
  const runs=new Set(),requests=new Set(),challenges=new Set();
  for(let i=0;i<10;i++){
    const pin=v.expected.stages[i],s=v.stages[i];exact(pin,PINS);
    for(const k of PINS.filter(k=>k.endsWith('_sha256')))need(hash(pin[k]),'invalid admitted stage '+k);
    const role=pin.stage_id==='primary-review'?'primary-review':pin.stage_id.split('-')[0];same(pin.role,role,'admitted role');same(pin.judge_index,role==='primary-review'?null:Number(pin.stage_id.at(-1)),'admitted judge');
    need(typeof pin.run_id==='string'&&/^[a-z0-9][a-z0-9-]{0,62}$/.test(pin.run_id),'native run ID');
    need(!runs.has(pin.run_id)&&!requests.has(pin.request_sha256),'distinct stage run/request');runs.add(pin.run_id);requests.add(pin.request_sha256);
    same(pin.source_tree_sha256,['generate','base'].includes(role)?v.expected.base_tree_sha256:v.expected.candidate_tree_sha256,'admitted stage source');
    exact(s,['stage_id','context','input_commitment','files','receipt_status','exit_code','input_slots','driver_sha256','driver_execution','native','output_bundle']);validateContext(s.context);validateOutputBundle(s.output_bundle);
    exact(s.native,modern?['base_vm','base_vm_launch','receipt_run_id_policy']:['base_vm','base_vm_launch']);
    for(const k of ['base_vm','base_vm_launch'])need(s.native[k]&&Object.getPrototypeOf(s.native[k])===Object.prototype&&Object.keys(s.native[k]).length>0,'independent native base/launch pin required');
    if(modern)validateReceiptPolicy(s.native.receipt_run_id_policy,s.native);
    need(!challenges.has(s.context.subject.challenge),'distinct stage challenge');challenges.add(s.context.subject.challenge);
    exact(s.input_commitment,['alg','scope','inputs_sha256']);same(s.input_commitment.alg,'dsmack.task-commitment/3','public input commitment algorithm');
    need(hash(s.input_commitment.inputs_sha256),'admitted public input digest');
    // Complete selection coverage is authorized by the independent public-input
    // audit, not inferred from a worker-provided descriptor or report flag.
    exact(s.input_commitment.scope,['include','file_slots']);same(s.input_commitment.scope.include,['files'],'public file scope');
    const slots=s.input_commitment.scope.file_slots;need(Array.isArray(slots)&&slots.length>0&&slots.length<=64&&slots.every(x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(x)),'public input file slots');same(slots,[...new Set(slots)].sort(),'public input slot order');validateInputSelection(s,pin);
    need(s.files&&Object.getPrototypeOf(s.files)===Object.prototype&&Object.keys(s.files).length>0&&Object.keys(s.files).length<=64,'artifact map required');
    for(const [name,artifact] of Object.entries(s.files))need(/^[a-z][a-z0-9.-]{0,79}$/.test(name)&&typeof artifact==='string'&&(s.output_bundle===null?/^[a-z][a-z0-9-]{0,62}$/:/^[a-z][a-z0-9.-]{0,79}$/).test(artifact),'artifact map names');
    need(new Set(Object.values(s.files)).size===Object.keys(s.files).length&&Object.hasOwn(s.files,'checks.json'),'unique checks artifact map');
    if(role==='generate')need(Object.hasOwn(s.files,'suite.json'),'generation suite artifact required');
    need(role==='base'?s.receipt_status==='failed'&&s.exit_code===1:s.receipt_status==='completed'&&s.exit_code===0,'admitted classified driver outcome');
  }
  same(v.expected.stages[9].request_sha256,v.expected.primary_request_sha256,'primary request');
  if(modern){taskImageBinding(v.task,v.stages,v.expected.stages[9]);validateHarnessBinding(v.harness_binding,v.task,v.expected,v.stages);}
  else same(v.expected.stages[9].oci_manifest_sha256,v.task.image_sha256,'primary task image');
  exact(v.delivery,['bundle_artifact','candidate_manifest_artifact']);
  const primary=v.stages[9];
  need(v.delivery.bundle_artifact!==v.delivery.candidate_manifest_artifact,'distinct delivery artifacts');
  for(const name of Object.values(v.delivery))need(Object.values(primary.files).includes(name),'authenticated delivery artifact required');
}
export class AcceptanceAdapter {
  #admissions; #reportKeys;
  constructor({store,admissions,reportKeys}) {
    this.store=store;need(admissions&&Object.getPrototypeOf(admissions)===Object.prototype,'trusted admissions required');
    this.#admissions=JSON.parse(canonical(admissions));this.#reportKeys={};
    need(reportKeys&&Object.getPrototypeOf(reportKeys)===Object.prototype,'configured original report keys required');
    for(const [id,raw] of Object.entries(reportKeys))this.#reportKeys[id]=reportKey(raw);
    for(const [id,v] of Object.entries(this.#admissions)){
      validateAdmission(v);same(v.task.attempt_id,id,'admission assignment');
      for(const stage of v.stages)need(this.#reportKeys[stage.context.verifier.key_id],'admitted report trust root not configured');
    }
  }
  evaluate(attemptId,input) {
    const admission=this.#admissions[attemptId];need(admission,'attempt acceptance not independently admitted',403);
    same(snapshot(this.store,attemptId),admission.task,'immutable application assignment');
    const a=this.store.attempt(attemptId);need(['submitted','verified'].includes(a.state),'submitted attempt required',409);
    exact(input,['requestBytes','resultsBytes','originals']);
    const request=document(input.requestBytes,131072);exact(request,['schema','task_id','task_terms_sha256','attempt_id','attempt_nonce','run_id','run_role','acceptance_profile_sha256','base','candidate','toolchain','required_artifacts']);
    const t=this.store.task(a.task_id),e=admission.expected;
    for(const [k,v] of Object.entries({schema:'dsmack-bounty-public-request/1',task_id:t.id,task_terms_sha256:t.terms_sha256,attempt_id:a.id,attempt_nonce:a.nonce,run_id:e.stages[9].run_id,run_role:'review',acceptance_profile_sha256:t.checker_sha256}))same(request[k],v,'primary request '+k);
    exact(request.base,['repo','commit','tree_manifest_sha256']);same(request.base,{repo:'https://github.com/'+t.repo,commit:t.base_commit,tree_manifest_sha256:e.base_tree_sha256},'primary base');
    exact(request.candidate,['upstream_commit','tree_manifest_sha256','admission_transform_sha256']);
    need(request.candidate.upstream_commit===null||typeof request.candidate.upstream_commit==='string'&&/^[0-9a-f]{40}$/.test(request.candidate.upstream_commit),'candidate commit');need(hash(request.candidate.admission_transform_sha256),'candidate admission transform');
    same(request.candidate.tree_manifest_sha256,a.candidate_sha256,'primary candidate');same(request.toolchain,{platform:'linux/arm64',image_digest:'sha256:'+(admission.schema===ADMISSION2?e.stages[9].oci_manifest_sha256:t.image_sha256)},'primary toolchain');
    need(Array.isArray(request.required_artifacts)&&request.required_artifacts.length>0&&request.required_artifacts.length<=32&&request.required_artifacts.every(x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(x)),'primary required artifacts');same(request.required_artifacts,[...new Set(request.required_artifacts)].sort(),'primary artifact order');
    same(sha(Buffer.concat([Buffer.from(request.schema+'\0'),input.requestBytes])),e.primary_request_sha256,'primary public request digest');
    // Canonical/size checks happen before the internal transport is allocated.
    const results=document(input.resultsBytes,262144);
    need(Array.isArray(results.stages)&&results.stages.length===10,'closed result stages required');same(results.stages.map(s=>s.stage_id),STAGES,'closed result stage order');
    need(Array.isArray(input.originals)&&input.originals.length===10,'ten original proofs required');same(input.originals.map(x=>x.stage_id),STAGES,'closed sorted original proofs');
    const outputs={},measured={},verifiedStages={};let total=0;
    for(let i=0;i<10;i++){
      const original=input.originals[i],s=admission.stages[i],pin=e.stages[i];
      need(Buffer.isBuffer(original.manifestBytes)&&Buffer.isBuffer(original.receiptBytes),'original manifest/receipt bytes required');
      const verified=verifyOriginalStage(original,s,pin,this.#reportKeys);verifiedStages[s.stage_id]=verified;
      measured[s.stage_id]=authenticateMeasuredInputs(original,s,pin,e,admission.task,results.stages[i],input.requestBytes);
      total+=Object.values(verified.files).reduce((n,b)=>n+b.length,0);need(total<=64*1024*1024,'acceptance aggregate output bound');
      outputs[s.stage_id]={manifest_b64:verified.manifestBytes.toString('base64'),files:Object.fromEntries(Object.entries(verified.files).map(([k,b])=>[k,b.toString('base64')])),workload_status:verified.workload_status,report_sha256:verified.report_sha256};
    }
    // Both full bundles have already authenticated above, including their
    // exact source manifest membership/bytes. Recompute the limited transform
    // relation here; a trusted declaration alone never substitutes for it.
    const primaryProfile=document(measured['primary-review'].file('stage_profile'),262144);
    const transform=primaryProfile.admission_transform;
    exact(transform,['record','sha256']);
    same(transform.sha256,request.candidate.admission_transform_sha256,'primary transform selection');
    verifySourceRelation({baseManifestBytes:measured['base-1'].file('source_manifest'),
      candidateManifestBytes:measured['primary-review'].file('source_manifest'),
      transformBytes:encoded(transform.record),expectedBase:e.base_tree_sha256,
      expectedCandidate:e.candidate_tree_sha256,expectedTransform:transform.sha256});
    const primary=input.originals[9],bundleBytes=verifiedStages['primary-review'].artifactFiles[admission.delivery.bundle_artifact],candidateManifestBytes=verifiedStages['primary-review'].artifactFiles[admission.delivery.candidate_manifest_artifact];
    if(admission.schema!==ADMISSION2)same(receiptDocument(primary.receiptBytes).harness_sha256,t.harness_sha256,'primary task harness');
    same(sha(bundleBytes),a.bundle_sha256,'authenticated delivery bundle');verifySourceDelivery(bundleBytes,candidateManifestBytes,a.candidate_sha256);
    for(const name of request.required_artifacts)need(Object.hasOwn(primary.outputs,'artifact:'+name),'required primary artifact missing');
    // A private temporary regular stdin descriptor also works in sandboxes that
    // forbid pipe shutdown. No pathname or executable is accepted from input.
    const scratch=mkdtempSync(join(tmpdir(),'dsmack-closed-join-'));let fd,child;
    try {
      const path=join(scratch,'stdin');
      writeFileSync(path,encoded({expected:e,results_b64:input.resultsBytes.toString('base64'),outputs}),{mode:0o600,flag:'wx'});
      fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
      child=spawnSync('/usr/bin/python3',['-I','-B',joinPath],{stdio:[fd,'pipe','pipe'],encoding:null,maxBuffer:1048576,timeout:30000,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}});
    } finally {if(fd!==undefined)closeSync(fd);rmSync(scratch,{recursive:true,force:true});}
    need(!child.error&&child.status===0,'closed acceptance join refused');
    const joined=document(child.stdout,4096);exact(joined,['accepted','acceptance_results_sha256','execution_evidence_sha256']);
    need(joined.accepted===true&&hash(joined.acceptance_results_sha256)&&hash(joined.execution_evidence_sha256),'closed join success required');
    const reportBytes=encoded({schema:'dsmack-bounty-acceptance-report/1',request_sha256:e.primary_request_sha256,task_terms_sha256:t.terms_sha256,acceptance_profile_sha256:t.checker_sha256,attempt_id:a.id,attempt_nonce:a.nonce,run_id:request.run_id,run_role:request.run_role,candidate_tree_manifest_sha256:a.candidate_sha256,bundle_sha256:a.bundle_sha256,execution_evidence_sha256:joined.execution_evidence_sha256,acceptance_results_sha256:joined.acceptance_results_sha256,accepted:true});
    const deliveryBytes=encoded({schema:'dsmack-bounty-delivery-manifest/1',request_sha256:e.primary_request_sha256,attempt_id:a.id,candidate_sha256:a.candidate_sha256,bundle_sha256:a.bundle_sha256,bundle_bytes:bundleBytes.length,report_sha256:sha(reportBytes)});
    return {reportBytes,deliveryBytes,bundleBytes,candidateManifestBytes,expected:{request_sha256:e.primary_request_sha256,run_id:request.run_id,run_role:request.run_role,execution_evidence_sha256:joined.execution_evidence_sha256,acceptance_results_sha256:joined.acceptance_results_sha256,...(admission.schema===ADMISSION2?{image_binding:taskImageBinding(admission.task,admission.stages,e.stages[9])}:{})}};
  }
  admit(attemptId,input,certificate) {
    const result=this.evaluate(attemptId,input);
    need(certificate?.payload?.accepted===true&&certificate.payload.report_sha256===sha(result.reportBytes),'certificate must bind complete authenticated acceptance',403);
    // Store validates configured application signer, all assignment fields,
    // freshness on first admission and immutable retries in its own transaction.
    return this.store.verdict(attemptId,certificate);
  }
}
