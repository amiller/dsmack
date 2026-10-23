// Application semantics over a canonical PUBLIC file-only projection.
// NEVER accept/export the private VDE envelope; its original is checked only by
// the genuine guest/full verifier. The signed task3 receipt binds actual files.
// Native support/admission for OPTIONAL public-file commitments is a separate
// qualification gate. The old diagnostic has no such commitment and refuses.
import { exact, need, sha } from '../bounty-demo/core.mjs';
import { document, encoded, same, hash } from './original-report.mjs';
import { verifySourceDelivery } from './source-delivery.mjs';
const names=['request','task_terms','acceptance_profile','plan','stage_profile','driver','source_manifest','source_bundle','suite'];
export function validateInputSelection(stage,pin) {
  exact(stage.driver_execution,['entrypoint','command']);
  const invocation=stage.driver_execution;
  need([['/usr/bin/node'],['/usr/local/bin/node'],['/usr/bin/python3'],['/usr/bin/python3','-I'],['/usr/bin/python3','-I','-B']].some(v=>JSON.stringify(v)===JSON.stringify(invocation.entrypoint)),'unsupported admitted driver interpreter argv');
  need(Array.isArray(invocation.command)&&invocation.command.length>0&&invocation.command.length<=64&&invocation.command.every(v=>typeof v==='string'&&v.length>0&&v.length<=1024&&!/[\x00-\x1f\x7f]/.test(v))&&invocation.command[0].startsWith('/'),'supported admitted driver script argv required');
  exact(stage.input_slots,names);need(hash(stage.driver_sha256),'independent driver digest');
  const values=[];
  for(const [purpose,slot] of Object.entries(stage.input_slots)){
    if(purpose==='suite'&&!['base','candidate'].includes(pin.role)){same(slot,null,'no generation/primary suite input');continue;}
    need(typeof slot==='string'&&/^[a-z][a-z0-9-]{0,62}$/.test(slot),'measured input slot');values.push(slot);
  }
  need(values.length===new Set(values).size,'distinct measured input slots');
  same(stage.input_commitment.scope.file_slots,values.sort(),'complete semantic input selection');
}
export function authenticateMeasuredInputs(original,stage,pin,expected,task,row,primaryRequestBytes) {
  const raw=original.publicInputsBytes;need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=64*1024*1024,'original measured public file projection required');
  const envelope=document(raw,64*1024*1024);exact(envelope,['runtime_input_version','manifest_sha256','files','commitments']);
  same(envelope.runtime_input_version,4,'generic runtime input version');same(envelope.manifest_sha256,stage.context.subject.manifest_sha256,'measured input manifest');
  const manifest=JSON.parse(original.manifestBytes),allowed=manifest.allowed_files;
  need(Array.isArray(allowed)&&allowed.length<=64,'declared measured files');
  need(allowed.every(f=>f&&f.audience!=='broker'),'broker-file variant unsupported without private input validation');
  need(allowed.every(f=>f.audience==='workload'&&f.required===true),'only required workload public file declarations supported');
  const compose=JSON.parse(manifest.docker_compose_file),services=Object.values(compose.services);
  need(Array.isArray(manifest.allowed_envs)&&Array.isArray(manifest.required_envs),'manifest env declarations required');
  const envNames=[];
  for(const env of manifest.allowed_envs){
    exact(env,['name','audience'],['services']);
    need(pin.role==='generate'&&env.audience==='broker'&&typeof env.name==='string'&&/^[A-Za-z_][A-Za-z0-9_]*$/.test(env.name)&&!envNames.includes(env.name),'only separately declared generator broker env supported');envNames.push(env.name);
    if(Object.hasOwn(env,'services'))need(Array.isArray(env.services)&&env.services.length>0&&new Set(env.services).size===env.services.length&&env.services.every(n=>Object.hasOwn(compose.services,n)),'declared broker env service selection');
  }
  need(manifest.required_envs.every(n=>envNames.includes(n))&&new Set(manifest.required_envs).size===manifest.required_envs.length,'required broker env declarations');
  need(services.length===1,'one admitted stage driver service required');
  const service=services[0];same({entrypoint:service.entrypoint,command:service.command},stage.driver_execution,'exact admitted driver argv');need(Array.isArray(service.volumes)&&service.volumes.length<=80,'stage driver mounts required');
  const targets=new Set();
  need(Array.isArray(envelope.files)&&envelope.files.length<=64,'measured file count');
  const files={},selected=[];let total=0;
  for(const f of envelope.files){
    exact(f,['slot','content_base64']);need(typeof f.slot==='string'&&/^[a-z][a-z0-9-]{0,62}$/.test(f.slot)&&!Object.hasOwn(files,f.slot),'unique measured file slot');
    need(typeof f.content_base64==='string'&&f.content_base64.length<=24*1024*1024,'measured file base64 bound');
    const data=Buffer.from(f.content_base64,'base64');need(data.toString('base64')===f.content_base64&&data.length<=16*1024*1024,'canonical measured file bytes');
    total+=data.length;need(total<=32*1024*1024,'measured input aggregate bound');files[f.slot]=data;selected.push(f);
    const declarations=allowed.filter(a=>a.slot===f.slot);need(declarations.length===1,'unique consumed file declaration');
    const declaration=declarations[0];
    need(declaration.audience==='workload'&&declaration.required===true&&declaration.mode==='ro'&&Number.isSafeInteger(declaration.max_bytes)&&data.length<=declaration.max_bytes,'declared read-only workload file');
    need(typeof declaration.target==='string'&&/^\/[A-Za-z0-9._/-]{1,255}$/.test(declaration.target)&&declaration.target.split('/').slice(1).every(x=>x&&x!=='.'&&x!=='..')&&!targets.has(declaration.target),'unique safe measured target');targets.add(declaration.target);
    need(service.volumes.filter(v=>v===f.slot+':'+declaration.target+':ro').length===1,'measured file mounted read-only in admitted driver');
    if(f.slot===stage.input_slots.driver)same(stage.driver_execution.command[0],declaration.target,'admitted script is measured driver');
  }
  same(Object.keys(files).sort(),stage.input_commitment.scope.file_slots,'closed measured files');same(allowed.map(f=>f.slot).sort(),Object.keys(files).sort(),'closed manifest file declarations');
  selected.sort((a,b)=>a.slot<b.slot?-1:a.slot>b.slot?1:0);
  const commitment={alg:'dsmack.task-commitment/3',scope:{include:['files'],file_slots:Object.keys(files).sort()},inputs_sha256:sha(encoded(['dsmack.task-commitment/3',envelope.manifest_sha256,{include:['files'],file_slots:Object.keys(files).sort()},{files:selected}]))};
  same(envelope.commitments,commitment,'recomputed original public file commitment');same(commitment,stage.input_commitment,'independent measured file commitment');
  const file=purpose=>files[stage.input_slots[purpose]];
  same(sha(file('task_terms')),task.terms_sha256,'measured task terms');same(sha(file('acceptance_profile')),task.checker_sha256,'measured acceptance profile');
  same(sha(file('plan')),expected.plan_sha256,'measured stage plan');same(sha(file('stage_profile')),pin.stage_profile_sha256,'measured stage profile');same(sha(file('driver')),stage.driver_sha256,'measured trusted driver');
  if(pin.role==='generate'){
    const profile=document(file('stage_profile'),262144),spec=profile.specification;
    exact(spec,['text','sha256']);need(typeof spec.text==='string'&&Buffer.byteLength(spec.text)>0&&Buffer.byteLength(spec.text)<=131072&&hash(spec.sha256),'generation specification text and SHA required');same(sha(Buffer.from(spec.text)),spec.sha256,'generation specification bytes');
  }
  verifySourceDelivery(file('source_bundle'),file('source_manifest'),pin.source_tree_sha256);
  const request=document(file('request'),131072);
  need(typeof request.schema==='string'&&request.schema.length<=80,'measured request schema');
  same(sha(Buffer.concat([Buffer.from(request.schema+'\0'),file('request')])),pin.request_sha256,'independent measured stage request');
  if(pin.role==='primary-review')same(file('request').toString('base64'),primaryRequestBytes.toString('base64'),'original measured primary request');
  else {
    // NEW proposed APPLICATION child request, not a generic runner wire format.
    // It carries no candidate source/digest into the independent generator.
    exact(request,['schema','task_id','task_terms_sha256','acceptance_profile_sha256','plan_sha256','attempt_id','attempt_nonce','payee','run_id','stage_id','role','judge_index','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256','input_suite_sha256','requested_model']);
    const want={schema:'dsmack-bounty-child-request/1',task_id:task.task_id,task_terms_sha256:task.terms_sha256,acceptance_profile_sha256:task.checker_sha256,plan_sha256:expected.plan_sha256,attempt_id:task.attempt_id,attempt_nonce:task.nonce,payee:task.payee,requested_model:expected.requested_model,input_suite_sha256:row.input_suite_sha256};
    for(const k of ['run_id','stage_id','role','judge_index','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256'])want[k]=pin[k];same(request,want,'measured child request semantics');
  }
  if(['base','candidate'].includes(pin.role))same(sha(file('suite')),row.input_suite_sha256,'actual measured CI suite bytes');
  return {files,file};
}
