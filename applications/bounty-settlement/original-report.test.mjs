// REAL unchanged public signed diagnostic, reused read-only. Never acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sha } from '../bounty-demo/core.mjs';
import { authenticateOriginalReport, reportKey, encoded, document } from './original-report.mjs';
import { AcceptanceAdapter } from './acceptance-adapter.mjs';
import { syntheticAdapterFixture } from './adapter-fixture.mjs';
const root=new URL('./fixtures/genuine-diagnostic/',import.meta.url);
const reportBytes=readFileSync(new URL('report.json',root)),receiptBytes=readFileSync(new URL('receipt.json',root)),envelopeBytes=readFileSync(new URL('result-envelope.json',root));
const keyId='dsmack-root-demo-c01615dc-20261022',publicKey='0rs+/3i5MhAVbhkDtpngWfazI5CCVUXqGWlpKFZr8Q4=';
// These independent expected subjects are pinned in source, not extracted from
// the incoming signed report, checker stdout or an uploaded verified flag.
const context={verifier:{id:'dsmack-runresult-verifier',version:'2',key_id:keyId},verifier_context:{core_sha256:'13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5',enrollment_sha256:'0698824f6a7e48378f2d0a9de67867d3ae07a25ed6359f439e0cf6ef7a857162',extraction_contract:'dsmack.safe-extract-result/1',extractor_tool_sha256:'d8d3959fe11b32233f4291b795cb4ce2b8b8e6cbd2a467eebecedfe943a6dcd2'},subject:{manifest_sha256:'8f63aba0dcfb1a4d186de2d8f2dd0577eb469d671aec398f27900eaa1214b7fa',receipt_selector:'bounty-board-search-browser-review-v1',challenge:'00084990dd7b93935348bac28ef896d9de203d951e6ea0458ad7f4f88d383f22',key_id_b64:'CbXoqVY6kPKTOUAZblbCm2oJcRyHcJGEqjsMfqCV3hI=',receipt_environment:'vm'}};
const keys={[keyId]:reportKey(publicKey)};
test('REAL original report signature and raw LF receipt authenticate with independent public subjects',()=>{
  assert.equal(sha(reportBytes),'08c01b1c8f04111ea3e55f607d2da4a0ec0334f66afeb895d83f4a8614764e5f');
  assert.equal(sha(receiptBytes),'573ce0807107e5ffc4f418274b8030f957fbe26d046a7a164e50ee8dec981b41');
  const {report,receipt}=authenticateOriginalReport({reportBytes,receiptBytes},context,keys);
  assert.equal(receiptBytes.at(-1),10);assert.equal(receipt.environment,'vm');assert.equal(report.subject.receipt_environment,'vm');
  assert.equal(report.apple.environment,'production');assert.equal(report.subject.evidence_class,'apple-hardware-assertion');assert.equal(report.subject.result_counter,2);
  assert.equal(receipt.runtime_inputs_commitment,null);assert.equal(report.subject.commitment_status,'absent');
  assert.equal(sha(envelopeBytes),'5722a91a46e8fd19d5d90d364f18bcde05513151d11d9065402aedb7b5f84492');
  const envelope=document(envelopeBytes);assert.equal(sha(encoded(['dsmack.run-result-envelope/1',envelope])),report.subject.envelope_sha256);
  assert.equal(envelope.result_disk.sha256,report.subject.result_image_sha256);assert.equal(envelope.launch.evidence_sha256,report.subject.launch_evidence_sha256);
});
test('REAL report refuses changed context, environment relabel, signature forgery and receipt LF loss',()=>{
  for(const change of [c=>c.subject.challenge='wrong',c=>c.subject.receipt_environment='mac-attested',c=>c.subject.manifest_sha256='0'.repeat(64),c=>c.verifier_context.enrollment_sha256='0'.repeat(64)]){
    const expected=structuredClone(context);change(expected);assert.throws(()=>authenticateOriginalReport({reportBytes,receiptBytes},expected,keys));
  }
  assert.throws(()=>authenticateOriginalReport({reportBytes,receiptBytes:receiptBytes.subarray(0,-1)},context,keys),/original receipt bytes/);
  const forged=document(reportBytes);forged.subject.receipt_environment='mac-attested';assert.throws(()=>authenticateOriginalReport({reportBytes:encoded(forged),receiptBytes},context,keys),/signature/);
  assert.throws(()=>authenticateOriginalReport({reportBytes,receiptBytes},context,{}),/trust root/);
});
test('REAL genuinely signed diagnostic refuses full acceptance alongside nine synthetic child proofs',()=>{
  const f=syntheticAdapterFixture();try{
    f.reportKeys[keyId]=publicKey;f.admissions[f.attemptId].stages[9].context=context;
    // The source fixture is independently fixed by its raw SHA above, not the
    // incoming stage record. Select its complete native closure for this control.
    const selectedNative=JSON.parse(receiptBytes);f.admissions[f.attemptId].stages[9].native={base_vm:selectedNative.base_vm,base_vm_launch:selectedNative.base_vm_launch};
    f.input.originals[9]={stage_id:'primary-review',reportBytes,receiptBytes,manifestBytes:readFileSync(new URL('manifest.json',root)),publicInputsBytes:Buffer.alloc(0),outputs:{}};
    const adapter=new AcceptanceAdapter(f);
    assert.throws(()=>adapter.evaluate(f.attemptId,f.input),/measured public input commitment required/);
    assert.equal(f.store.attempt(f.attemptId).state,'submitted');
    f.input.originals=[f.input.originals[9]];assert.throws(()=>adapter.evaluate(f.attemptId,f.input),/ten original proofs/);
  }finally{f.store.close();}
});
