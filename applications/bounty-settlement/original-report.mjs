// Read-only reuse of ORIGINAL signed full-verifier reports. No replay/key store IO.
import { createPublicKey, verify } from 'node:crypto';
import { constants, openSync, closeSync, fstatSync, readSync, lstatSync, readdirSync } from 'node:fs';
import { resolve, parse, join } from 'node:path';
import { canonical, sha, exact, need } from '../bounty-demo/core.mjs';
import { expandOutputBundle } from './output-bundle.mjs';
import { validateReceiptRunId } from './admission-identities.mjs';

export const encoded = value => Buffer.from(canonical(value));
export const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function same(a,b,label) { need(canonical(a)===canonical(b),'binding mismatch: '+label); }
export function document(raw,cap=1048576) {
  need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=cap,'document byte bound');
  let value; try { value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)); } catch { need(false,'invalid JSON/UTF8'); }
  function walk(v,depth=0) {
    need(depth<=24,'JSON nesting');
    if(typeof v==='string')need(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(v),'invalid Unicode scalar');
    if(Array.isArray(v))v.forEach(x=>walk(x,depth+1));
    else if(v&&typeof v==='object')for(const [k,x] of Object.entries(v)){walk(k,depth+1);walk(x,depth+1);}
  }
  walk(value); need(encoded(value).equals(raw),'canonical document required'); return value;
}
function b64(value,size) {
  need(typeof value==='string'&&value.length===4*Math.ceil(size/3),'base64 size');
  const raw=Buffer.from(value,'base64');need(raw.length===size&&raw.toString('base64')===value,'canonical base64 required');return raw;
}
export function reportKey(raw) {
  return createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),b64(raw,32)]),format:'der',type:'spki'});
}
const subjectKeys=['manifest_sha256','receipt_selector','challenge','key_id_b64','launch_evidence_sha256','envelope_sha256','pair_evidence_sha256','launch_counter','result_counter','result_image_sha256','result_image_bytes','console_sha256','console_bytes','receipt_path','receipt_sha256','receipt_evidence_sha256','export_index_sha256','receipt_environment','receipt_status','outputs_verified','commitment_status','evidence_class'];
const contextKeys=['core_sha256','extractor_tool_sha256','extraction_contract','enrollment_sha256'];
export function validateContext(context) {
  exact(context,['verifier','verifier_context','subject']);
  exact(context.verifier,['id','version','key_id']);
  need(context.verifier.id==='dsmack-runresult-verifier'&&context.verifier.version==='2','selected verifier identity required');
  need(typeof context.verifier.key_id==='string'&&context.verifier.key_id.length>0&&context.verifier.key_id.length<=128,'report key ID');
  exact(context.verifier_context,contextKeys);
  for(const k of contextKeys.filter(k=>k.endsWith('_sha256')))need(hash(context.verifier_context[k]),'verifier context digest');
  same(context.verifier_context.extraction_contract,'dsmack.safe-extract-result/1','extraction contract');
  exact(context.subject,['manifest_sha256','receipt_selector','challenge','key_id_b64','receipt_environment']);
  need(hash(context.subject.manifest_sha256),'expected manifest digest');
  need(/^[a-z0-9][a-z0-9-]{0,62}$/.test(context.subject.receipt_selector),'expected receipt selector');
  need(typeof context.subject.challenge==='string'&&context.subject.challenge.length>0&&context.subject.challenge.length<=4096,'expected challenge');
  b64(context.subject.key_id_b64,32);
  same(context.subject.receipt_environment,'vm','native VM receipt environment');
}
// Receipt bytes from the actual guest include a final LF. Preserve those bytes
// for the signed SHA; only parsing tolerates the single canonical JSON LF.
export function receiptDocument(raw) {
  need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=1048576,'receipt byte bound');
  return document(raw.at(-1)===10?raw.subarray(0,-1):raw);
}
export function authenticateOriginalReport({reportBytes,receiptBytes},context,reportKeys) {
  validateContext(context);
  const report=document(reportBytes);
  exact(report,['runresult_report_version','verifier','verifier_context','verified','subject','apple','report_sig']);
  same(report.runresult_report_version,2,'original report version');
  same(report.verifier,context.verifier,'expected verifier');
  same(report.verifier_context,context.verifier_context,'expected verifier context');
  const sig=report.report_sig;
  exact(sig,['alg','key_id','sig_b64']);same(sig.alg,'ed25519','report signature algorithm');
  same(sig.key_id,context.verifier.key_id,'expected report signer');
  const key=reportKeys[sig.key_id];need(key,'original report trust root not configured');
  const {report_sig:unused,...body}=report;
  need(verify(null,encoded(body),key,b64(sig.sig_b64,64)),'invalid original verifier signature',403);
  need(report.verified===true,'original verifier did not verify');
  const subject=report.subject;exact(subject,subjectKeys);
  for(const [k,v] of Object.entries(context.subject))same(subject[k],v,'original subject '+k);
  for(const k of subjectKeys.filter(k=>k.endsWith('_sha256')))need(hash(subject[k]),'original subject digest');
  need(Number.isSafeInteger(subject.launch_counter)&&subject.launch_counter>=0&&Number.isSafeInteger(subject.result_counter)&&subject.result_counter>subject.launch_counter,'original counter order');
  need(Number.isSafeInteger(subject.result_image_bytes)&&subject.result_image_bytes>=512&&Number.isSafeInteger(subject.console_bytes)&&subject.console_bytes>=0,'original retained sizes');
  same(subject.receipt_path,subject.receipt_selector+'/receipt.json','receipt selector path');
  need(subject.outputs_verified===true&&subject.evidence_class==='apple-hardware-assertion','production full-verifier evidence required');
  exact(report.apple,['assertion_counters_authenticated','receipt_status','environment','verified_at_unix_s']);
  need(report.apple.assertion_counters_authenticated===true&&report.apple.environment==='production'&&report.apple.receipt_status==='retained_not_validated'&&Number.isSafeInteger(report.apple.verified_at_unix_s)&&report.apple.verified_at_unix_s>=0,'production Apple report required');
  same(sha(receiptBytes),subject.receipt_sha256,'original receipt bytes');
  const receipt=receiptDocument(receiptBytes);
  same(receipt.manifest_sha256,subject.manifest_sha256,'receipt manifest');
  same(receipt.environment,subject.receipt_environment,'receipt environment');
  const receiptBody={attestation:null};
  for(const k of ['base_vm','base_vm_launch','harness_sha256','manifest_sha256','observed','outputs','run_id','runtime_inputs_commitment']) {
    need(Object.hasOwn(receipt,k),'original receipt field required');receiptBody[k]=receipt[k];
  }
  same(sha(encoded(['dsmack.receipt-evidence/4',receiptBody])),subject.receipt_evidence_sha256,'original receipt evidence');
  same(receipt.outputs.status,subject.receipt_status,'signed workload status');
  return {report,receipt,report_sha256:sha(reportBytes)};
}
export function verifyOriginalStage(original,stage,pin,reportKeys) {
  exact(original,['stage_id','reportBytes','receiptBytes','manifestBytes','publicInputsBytes','outputs']);
  need(Buffer.isBuffer(original.manifestBytes)&&original.manifestBytes.length>0&&original.manifestBytes.length<=1048576,'manifest byte bound');
  same(original.stage_id,pin.stage_id,'original stage');
  const {report,receipt}=authenticateOriginalReport(original,stage.context,reportKeys);
  same(receipt.base_vm,stage.native.base_vm,'independently admitted native base_vm');
  same(receipt.base_vm_launch,stage.native.base_vm_launch,'independently admitted native base_vm_launch');
  const subject=report.subject;
  need(['recorded-unchecked','bound-to-validated-envelope'].includes(subject.commitment_status),'measured public input commitment required');
  same(sha(original.manifestBytes),subject.manifest_sha256,'original manifest bytes');
  // Native manifest bytes need not be canonical JSON (the actual producer indents).
  // They are independently selected by exact SHA before being parsed here.
  let manifest;try{manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(original.manifestBytes));}catch{need(false,'invalid original manifest');}
  same(manifest.image_platform,{architecture:'arm64',os:'linux'},'stage platform');
  const services=JSON.parse(manifest.docker_compose_file).services;
  need(services&&Object.keys(services).length>0&&Object.keys(services).length<=16,'stage services');
  need(Object.values(services).every(s=>typeof s.image==='string'&&s.image.endsWith('@sha256:'+pin.oci_manifest_sha256)),'stage OCI image');
  const native_receipt_run_id=validateReceiptRunId(receipt,manifest,subject,pin,stage.native);
  same(receipt.harness_sha256,manifest.harness?.sha256,'receipt harness');
  same(receipt.runtime_inputs_commitment,stage.input_commitment,'admitted public input commitment');
  const o=receipt.outputs;exact(o,['status','exit_code','stdout','stderr','artifacts','missing','started_unix_s','ended_unix_s','cancel']);
  same(o.status,subject.receipt_status,'signed workload status');same(o.status,stage.receipt_status,'expected workload status');
  same(o.exit_code,stage.exit_code,'expected workload exit');need(o.cancel===null,'cancelled work');
  need(Array.isArray(o.missing)&&o.missing.length===0,'missing original artifacts');
  need(Array.isArray(o.artifacts)&&o.artifacts.length>0&&o.artifacts.length<=64,'artifact count');
  need(original.outputs&&Object.getPrototypeOf(original.outputs)===Object.prototype,'original outputs required');
  const declared={};
  for(const name of ['stdout','stderr'])if(o[name]!==null){exact(o[name],['bytes','sha256']);declared['stream:'+name]=o[name];}
  for(const row of o.artifacts){exact(row,['name','bytes','sha256']);need(typeof row.name==='string'&&/^[a-z][a-z0-9-]{0,62}$/.test(row.name),'artifact name');need(!Object.hasOwn(declared,'artifact:'+row.name),'duplicate receipt artifact');declared['artifact:'+row.name]=row;}
  same(Object.keys(original.outputs).sort(),Object.keys(declared).sort(),'closed original outputs');
  let total=0;
  for(const [label,row] of Object.entries(declared)) {
    const raw=original.outputs[label];need(Buffer.isBuffer(raw)&&Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=16*1024*1024&&hash(row.sha256),'output byte declaration');
    total+=raw.length;need(total<=64*1024*1024&&raw.length===row.bytes&&sha(raw)===row.sha256,'authenticated output bytes');
  }
  let files,manifestBytes,artifactFiles;
  if(stage.output_bundle!==null){
    ({files,manifestBytes}=expandOutputBundle(original.outputs,stage.output_bundle,stage.files));artifactFiles=files;
  }else{
    files={};for(const [name,artifact] of Object.entries(stage.files))files[name]=original.outputs['artifact:'+artifact];
    same(Object.values(stage.files).sort(),o.artifacts.map(x=>x.name).sort(),'closed application artifact mapping');
    manifestBytes=encoded({schema:'dsmack-bounty-output-manifest/1',files:Object.keys(files).sort().map(name=>({name,size:files[name].length,sha256:sha(files[name])}))});
    artifactFiles=Object.fromEntries(Object.entries(stage.files).map(([name,artifact])=>[artifact,files[name]]));
  }
  let workload_status='completed';
  if(pin.role==='base'){
    need(o.status==='failed'&&o.exit_code===1,'authenticated base assertion-failure exit required');
    const checks=document(files['checks.json']);
    need(checks.schema==='dsmack-bounty-ci-checks/1'&&checks.browser_started===true&&checks.completed===true&&checks.infrastructure_failed===false&&Array.isArray(checks.tests)&&checks.tests.length>0&&checks.tests.every(t=>t&&['passed','assertion_failed'].includes(t.status))&&checks.tests.some(t=>t.status==='assertion_failed'),'authenticated base assertion classifier required');
    workload_status='assertion_failed';
  }else need(o.status==='completed'&&o.exit_code===0,'authenticated successful stage exit required');
  return {manifestBytes,files,artifactFiles,workload_status,report_sha256:sha(original.reportBytes),native_receipt_run_id};
}

// Read only PUBLIC original retained files. Never open private envelope, image,
// enrollment/replay stores, HMAC or signing keys. Stable read-only staging is a
// prerequisite: Node has no openat directory-descriptor API.
function safePath(path,directory=false) {
  const absolute=resolve(path);let current=parse(absolute).root;
  for(const part of absolute.slice(current.length).split('/').filter(Boolean)){
    current=join(current,part);const st=lstatSync(current);need(!st.isSymbolicLink(),'retained path symlink');
    if(current!==absolute||directory)need(st.isDirectory(),'retained ancestor directory');
  }
  return absolute;
}
export function readPublicFile(path,cap=1048576) {
  const fd=openSync(safePath(path),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {
    const st=fstatSync(fd);need(st.isFile()&&st.nlink===1&&st.size<=cap,'bounded regular public file required');
    const data=Buffer.alloc(st.size+1);let n=0,got;
    while(n<data.length&&(got=readSync(fd,data,n,data.length-n,null))>0)n+=got;
    const after=fstatSync(fd);need(n===st.size&&after.size===st.size&&after.mtimeMs===st.mtimeMs&&after.ctimeMs===st.ctimeMs,'public file changed');return data.subarray(0,n);
  } finally {closeSync(fd);}
}
// Third argument is a pre-work retained PUBLIC projection, never private VDE.
export function loadRetainedStage(root,stageId,publicInputsBytes) {
  safePath(root,true);
  const reportBytes=readPublicFile(join(root,'report.json')),receiptBytes=readPublicFile(join(root,'receipt.json')),manifestBytes=readPublicFile(join(root,'manifest'));
  const receipt=receiptDocument(receiptBytes),o=receipt.outputs;need(o&&Array.isArray(o.artifacts)&&o.artifacts.length<=64,'retained receipt outputs');
  const wanted={streams:['stdout','stderr'].filter(name=>o[name]!==null),artifacts:o.artifacts.map(row=>row.name)};
  need(Array.isArray(o.missing)&&o.missing.length===0,'retained missing artifacts');
  const outputRoot=join(root,'outputs');safePath(outputRoot,true);
  need(readdirSync(outputRoot).every(name=>Object.hasOwn(wanted,name)),'unexpected output directory');
  const outputs={};let total=0;
  for(const [kind,names] of Object.entries(wanted)){
    need(names.length===new Set(names).size&&names.every(name=>typeof name==='string'&&/^[a-z][a-z0-9.-]{0,79}$/.test(name)),'retained output names');
    const dir=join(outputRoot,kind);
    if(names.length===0&&!readdirSync(outputRoot).includes(kind))continue;
    safePath(dir,true);same(readdirSync(dir).sort(),names.slice().sort(),'retained output membership');
    // Admit aggregate stat sizes before reading any content from this directory.
    const sizes=names.map(name=>{const st=lstatSync(join(dir,name));need(st.isFile()&&st.nlink===1&&st.size<=16*1024*1024,'retained output file type/size');return st.size;});
    need(total+sizes.reduce((a,b)=>a+b,0)<=64*1024*1024,'retained output aggregate bound');
    for(const name of names){const raw=readPublicFile(join(dir,name),Math.min(16*1024*1024,64*1024*1024-total));total+=raw.length;outputs[(kind==='streams'?'stream:':'artifact:')+name]=raw;}
  }
  return {stage_id:stageId,reportBytes,receiptBytes,manifestBytes,publicInputsBytes,outputs};
}
