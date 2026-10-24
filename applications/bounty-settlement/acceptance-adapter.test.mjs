// SYNTHETIC signatures ONLY. These controls do not qualify a genuine run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { Readable } from 'node:stream';
import { Store, sha } from '../bounty-demo/core.mjs';
import { AcceptanceAdapter } from './acceptance-adapter.mjs';
import { createAcceptanceApplication } from './acceptance-service.mjs';
import { encoded as bytes, document, loadRetainedStage, readPublicFile } from './original-report.mjs';
import { syntheticAdapterFixture as fixture, syntheticTar } from './adapter-fixture.mjs';
import { verifySourceDelivery } from './source-delivery.mjs';
import { project, treeIdentity } from './projection.mjs';
const adapter=f=>new AcceptanceAdapter(f);
function withFixture(fn){const f=fixture();try{return fn(f);}finally{f.store.close();}}
function changedOutput(f,stage,mutation){
  const original=f.input.originals.find(x=>x.stage_id===stage),s=f.admissions[f.attemptId].stages.find(x=>x.stage_id===stage),r=f.result.stages.find(x=>x.stage_id===stage);
  mutation(original.outputs);
  const files=Object.fromEntries(Object.entries(s.files).map(([name,a])=>[name,original.outputs['artifact:'+a]]));
  r.checks_sha256=sha(files['checks.json']);
  r.output_manifest_sha256=sha(bytes({schema:'dsmack-bounty-output-manifest/1',files:Object.keys(files).sort().map(name=>({name,size:files[name].length,sha256:sha(files[name])}))}));
  const receipt=document(original.receiptBytes);
  receipt.outputs.artifacts=Object.entries(files).map(([name,b])=>({name:s.files[name],bytes:b.length,sha256:sha(b)}));
  original.receiptBytes=bytes(receipt);
  f.resignOriginal(stage,report=>{report.subject.receipt_sha256=sha(original.receiptBytes);const body={attestation:null};for(const k of ['base_vm','base_vm_launch','harness_sha256','manifest_sha256','observed','outputs','run_id','runtime_inputs_commitment'])body[k]=receipt[k];report.subject.receipt_evidence_sha256=sha(bytes(['dsmack.receipt-evidence/4',body]));});
}
function changedMeasuredInputs(f,stage,mutation){
  const o=f.input.originals.find(x=>x.stage_id===stage),s=f.admissions[f.attemptId].stages.find(x=>x.stage_id===stage),row=f.result.stages.find(x=>x.stage_id===stage);
  const envelope=document(o.publicInputsBytes);mutation(envelope,s,row);
  const selected=envelope.files.slice().sort((a,b)=>a.slot<b.slot?-1:a.slot>b.slot?1:0),scope={include:['files'],file_slots:selected.map(f=>f.slot)};
  const commitment={alg:'dsmack.task-commitment/3',scope,inputs_sha256:sha(bytes(['dsmack.task-commitment/3',envelope.manifest_sha256,scope,{files:selected}]))};
  envelope.commitments=commitment;s.input_commitment=commitment;o.publicInputsBytes=bytes(envelope);
  const receipt=document(o.receiptBytes);receipt.runtime_inputs_commitment=commitment;o.receiptBytes=bytes(receipt);
  f.resignOriginal(stage,r=>{r.subject.receipt_sha256=sha(o.receiptBytes);const body={attestation:null};for(const k of ['base_vm','base_vm_launch','harness_sha256','manifest_sha256','observed','outputs','run_id','runtime_inputs_commitment'])body[k]=receipt[k];r.subject.receipt_evidence_sha256=sha(bytes(['dsmack.receipt-evidence/4',body]));});
}

test('complete synthetic original-report graph joins before certificate and unsigned projection',()=>withFixture(f=>{
  const a=adapter(f),result=a.evaluate(f.attemptId,f.input);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  const cert=f.certificate(result.reportBytes);assert.equal(a.admit(f.attemptId,f.input,cert).state,'verified');
  const chain={chain_id:'31337',contract:'0x'+'3'.repeat(40),task_id:'1',assignment_id:'2',assignment_task_id:'1',worker:f.admissions[f.attemptId].task.payee,package_hash:'0x'+f.task.terms_sha256,policy_hash:'0x'+f.task.checker_sha256,completion_pay_wei:'1',assignment_state:'Reserved'};
  const expected={...result.expected,chain:Object.fromEntries(['chain_id','contract','task_id','assignment_id','completion_pay_wei'].map(k=>[k,chain[k]]))};
  const proposal=project({store:f.store,attemptId:f.attemptId,...result,expected,requestBytes:f.input.requestBytes,chain});
  assert.equal(proposal.authority,'none');assert.equal(proposal.payment_received,false);assert.equal(f.store.attempt(f.attemptId).reward_status,'unpaid');
}));

test('every original signature and independent report subject is required',()=>{
  for(const mode of ['signature','verified-flag','wrong-key','challenge','manifest','enrollment','fixture-class','counter','environment','run','commitment','OCI','status','exit','console-size'])withFixture(f=>{
    const stage='candidate-2';
    if(mode==='signature')f.input.originals[4].reportBytes=Buffer.from('{}');
    else if(mode==='wrong-key')f.reportKeys['synthetic-original']=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64');
    else f.resignOriginal(stage,(r,o)=>{
      if(mode==='verified-flag')r.verified=false;
      if(mode==='challenge')r.subject.challenge='other';
      if(mode==='manifest')r.subject.manifest_sha256='0'.repeat(64);
      if(mode==='enrollment')r.verifier_context.enrollment_sha256='0'.repeat(64);
      if(mode==='fixture-class')r.subject.evidence_class='software-fixture-nonhardware';
      if(mode==='counter')r.subject.result_counter=r.subject.launch_counter;
      if(mode==='environment')r.apple.environment='development';
      if(mode==='console-size')r.subject.console_bytes=-1;
      if(['run','commitment','status','exit'].includes(mode)){
        const receipt=document(o.receiptBytes);
        if(mode==='run')receipt.run_id='prior-attempt';
        if(mode==='commitment')receipt.runtime_inputs_commitment.inputs_sha256='0'.repeat(64);
        if(mode==='status')receipt.outputs.status='cancelled';
        if(mode==='exit')receipt.outputs.exit_code=137;
        o.receiptBytes=bytes(receipt);r.subject.receipt_sha256=sha(o.receiptBytes);
      }
      if(mode==='OCI'){const m=JSON.parse(o.manifestBytes);m.docker_compose_file=JSON.stringify({services:{driver:{image:'local@sha256:'+'0'.repeat(64)}}});o.manifestBytes=bytes(m);r.subject.manifest_sha256=sha(o.manifestBytes);}
    });
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),undefined,mode);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  });
});

test('six-check diagnostic, stdout pass and fabricated authenticated handles never accept',()=>{
  for(const mode of ['diagnostic-only','diagnostic-primary','stdout','handle','missing','duplicate','unknown','reorder'])withFixture(f=>{
    if(mode==='diagnostic-only')f.input.originals=[f.input.originals[9]];
    if(mode==='diagnostic-primary')changedOutput(f,'primary-review',out=>out['artifact:checks-report']=bytes({schema:'dsmack-bounty-deterministic-browser/1',deterministic_pass:true,tests:Array(6).fill({status:'passed'}),accepted:false,payment_eligible:false}));
    if(mode==='stdout')changedOutput(f,'candidate-1',out=>out['artifact:checks-report']=Buffer.from('passed'));
    if(mode==='handle')f.input.originals[0]={stage_id:'base-1',verified:true,authenticated:true};
    if(mode==='missing')f.input.originals.pop();
    if(mode==='duplicate')f.input.originals[1]=f.input.originals[0];
    if(mode==='unknown')f.input.originals.push(f.input.originals[0]);
    if(mode==='reorder')f.input.originals.reverse();
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),undefined,mode);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  });
});

test('all output bytes including media, stderr and source delivery are authenticated',()=>{
  for(const label of ['artifact:checks-report','stream:stdout','stream:stderr','artifact:source-bundle','artifact:source-manifest','artifact:browser-video','artifact:browser-screenshot','artifact:browser-trace','artifact:extra'])withFixture(f=>{
    const o=f.input.originals[/source-|browser-/.test(label)?9:0];o.outputs[label]=Buffer.from('substituted');
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));
  });
  withFixture(f=>{delete f.input.originals[9].outputs['artifact:source-bundle'];assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));});
});

test('actual measured files are required; hash-only and unconsumed audit JSON cannot prove source',()=>{
  for(const purpose of ['task_terms','acceptance_profile','plan','stage_profile','driver','source_manifest','source_bundle','suite'])withFixture(f=>{
    changedMeasuredInputs(f,'candidate-1',(envelope,s)=>{
      // Even a selected commitment and signed receipt matching these substituted
      // bytes cannot bypass independent application/source/suite semantics.
      envelope.files.find(row=>row.slot===s.input_slots[purpose]).content_base64=Buffer.from('{"audit_passed":true}').toString('base64');
    });
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),undefined,purpose);
  });
  withFixture(f=>{delete f.input.originals[0].publicInputsBytes;assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));});
  withFixture(f=>{f.input.originals[0].publicInputsBytes=bytes({verified:true,inputs_sha256:f.admissions[f.attemptId].stages[0].input_commitment.inputs_sha256});assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));});
  withFixture(f=>{
    const o=f.input.originals[0],envelope=document(o.publicInputsBytes);envelope.files[0].content_base64=Buffer.from('different bytes').toString('base64');o.publicInputsBytes=bytes(envelope);
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/recomputed original public file commitment/);
  });
});

test('even a resigned child request and recomputed selected commitment cannot swap nonce',()=>withFixture(f=>{
  changedMeasuredInputs(f,'candidate-1',(envelope,s,row)=>{
    const file=envelope.files.find(row=>row.slot===s.input_slots.request),request=document(Buffer.from(file.content_base64,'base64'));request.attempt_nonce='0'.repeat(64);
    const raw=bytes(request);file.content_base64=raw.toString('base64');
    const digest=sha(Buffer.concat([Buffer.from(request.schema+'\0'),raw]));row.request_sha256=digest;f.admissions[f.attemptId].expected.stages.find(s=>s.stage_id==='candidate-1').request_sha256=digest;
  });
  assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/measured child request semantics/);
}));

test('signed wrong model, missing fixed checks, suites and self-classified infrastructure refuse',()=>{
  for(const [stage,mutate] of [
    ['generate-1',c=>c.observed_model='wrong-model'],
    ['primary-review',c=>c.fixed_browser_baselines=[true,true,true]],
    ['primary-review',c=>c.fixed_logic_baselines=[true,true,true]],
    ['primary-review',c=>c.feature_checks=[true,true,true,true,true,1]],
    ['base-1',c=>c.infrastructure_failed=true],
    ['base-1',c=>c.browser_started=false],
    ['base-1',c=>c.tests=[]],
    ['candidate-2',c=>c.suite_sha256='0'.repeat(64)],
    ['candidate-3',c=>c.tests=[{id:'judge-3-assertion',status:'assertion_failed'}]]
  ])withFixture(f=>{
    changedOutput(f,stage,out=>{const checks=document(out['artifact:checks-report']);mutate(checks);out['artifact:checks-report']=bytes(checks);});
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/closed acceptance join refused|authenticated base assertion classifier required/);
  });
});

test('stage/request/profile/source/nonce and assignment swaps fail closed',()=>{
  for(const field of ['run_id','request_sha256','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256','execution_evidence_sha256'])withFixture(f=>{
    f.result.stages[0][field]='0'.repeat(64);f.input.resultsBytes=bytes(f.result);assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));
  });
  for(const field of ['payee','nonce','candidate_sha256','bundle_sha256'])withFixture(f=>{
    const a=f.store.attempt(f.attemptId);a[field]='0'.repeat(64);f.store.saveAttempt(a);assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/immutable application assignment/);
  });
  withFixture(f=>{f.result.attempt_nonce='old-nonce';f.input.resultsBytes=bytes(f.result);assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));});
  withFixture(f=>{const original=f.input.originals[0];f.input.originals[1]={...original,stage_id:'base-2'};assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));});
});

test('prior-assignment originals refuse even under the same configured report root',()=>{
  const prior=fixture(),current=fixture();try{
    // Model one real long-lived report authority across different assignments.
    current.reportKeys=prior.reportKeys;
    current.input.originals[0]=prior.input.originals[0];
    assert.throws(()=>adapter(current).evaluate(current.attemptId,current.input),/challenge/);
    assert.equal(current.store.attempt(current.attemptId).state,'submitted');
  }finally{prior.store.close();current.store.close();}
});

test('duplicate keys, noncanonical stage results and absent input commitments refuse',()=>{
  withFixture(f=>{f.input.resultsBytes=Buffer.concat([f.input.resultsBytes,Buffer.from('\n')]);assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/canonical/);});
  withFixture(f=>{f.input.originals[0].reportBytes=Buffer.from('{"verified":true,"verified":true}');assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/canonical/);});
  withFixture(f=>{f.admissions[f.attemptId].stages[0].input_commitment=null;assert.throws(()=>adapter(f));});
  withFixture(f=>{f.input.originals[0].outputs={...f.input.originals[0].outputs,'artifact:missing-media':Buffer.alloc(0)};assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/closed original outputs/);});
});

test('constructor copies admissions and refuses incomplete/untrusted configuration',()=>withFixture(f=>{
  const a=adapter(f);f.admissions[f.attemptId].expected.requested_model='mutated-after-config';assert.doesNotThrow(()=>a.evaluate(f.attemptId,f.input));
  assert.throws(()=>new AcceptanceAdapter({...f,reportKeys:{}}),/trust root/);
  assert.throws(()=>new AcceptanceAdapter({...f,admissions:{[f.attemptId]:{verified:true}}}));
  f.admissions[f.attemptId].stages[1].context.subject.challenge=f.admissions[f.attemptId].stages[0].context.subject.challenge;
  assert.throws(()=>adapter(f),/distinct stage challenge/);
}));

test('certificate must bind complete report and configured signer, candidate and payee',()=>withFixture(f=>{
  const a=adapter(f),r=a.evaluate(f.attemptId,f.input);
  for(const cert of [f.certificate(Buffer.from('diagnostic')),f.certificate(r.reportBytes,{payee:'0x'+'9'.repeat(40)}),f.certificate(r.reportBytes,{candidate_sha256:'0'.repeat(64)}),{...f.certificate(r.reportBytes),key_id:'worker-key'},f.certificate(r.reportBytes,{accepted:false})]){
    assert.throws(()=>a.admit(f.attemptId,f.input,cert));assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  }
}));

test('first admission survives expiry/restart; stale initial admission refuses',()=>{
  const root=mkdtempSync(join(tmpdir(),'bounty-adapter-restart-'));let f;try{
    let now=1000;const path=join(root,'state.sqlite');f=fixture({dbPath:path,clock:()=>now});
    let a=adapter(f);const r=a.evaluate(f.attemptId,f.input),cert=f.certificate(r.reportBytes);a.admit(f.attemptId,f.input,cert);f.store.close();
    now=1300;f.store=new Store(path,{now:()=>now,verifierKeys:{'synthetic-application':f.appKey}});a=adapter(f);
    assert.equal(a.admit(f.attemptId,f.input,cert).verdict_received_at,1000);
    assert.deepEqual(a.evaluate(f.attemptId,f.input).reportBytes,r.reportBytes);
    assert.throws(()=>a.admit(f.attemptId,f.input,f.certificate(r.reportBytes,{issued_at:1300,expires_at:1400})),/conflicting verdict/);
  }finally{f?.store.close();rmSync(root,{recursive:true,force:true});}
  let now=1000;const stale=fixture({clock:()=>now});try{const a=adapter(stale),r=a.evaluate(stale.attemptId,stale.input);now=1300;assert.throws(()=>a.admit(stale.attemptId,stale.input,stale.certificate(r.reportBytes)),/stale verdict/);assert.equal(stale.store.attempt(stale.attemptId).state,'submitted');}finally{stale.store.close();}
});

test('source delivery parses bytes, rejects links/traversal/duplicates and mismatched source',()=>{
  const data=Buffer.from('source'),manifest=bytes([{path:'app.js',mode:420,bytes:data.length,sha256:sha(data)}]),candidate=treeIdentity(manifest),bundle=syntheticTar([{path:'app.js',mode:420,data}]);
  assert.doesNotThrow(()=>verifySourceDelivery(bundle,manifest,candidate));
  for(const bad of [bundle.subarray(0,-512),Buffer.concat([bundle,Buffer.alloc(512)]),syntheticTar([{path:'../app.js',mode:420,data}]),syntheticTar([{path:'app.js',mode:493,data}]),syntheticTar([{path:'app.js',mode:420,data:Buffer.from('other!')}]),syntheticTar([{path:'app.js',mode:420,data},{path:'app.js',mode:420,data}])])assert.throws(()=>verifySourceDelivery(bad,manifest,candidate));
  const link=syntheticTar([{path:'app.js',mode:420,data,type:50}]);assert.throws(()=>verifySourceDelivery(link,manifest,candidate),/regular file only/);
});

test('retained source loader reads only public bytes and refuses output/ancestor symlinks',()=>withFixture(f=>{
  const root=mkdtempSync(join(tmpdir(),'bounty-retained-'));try{
    const o=f.input.originals[0];writeFileSync(join(root,'report.json'),o.reportBytes);writeFileSync(join(root,'receipt.json'),o.receiptBytes);writeFileSync(join(root,'manifest'),o.manifestBytes);
    mkdirSync(join(root,'outputs/artifacts'),{recursive:true});mkdirSync(join(root,'outputs/streams'));
    for(const [label,raw] of Object.entries(o.outputs)){const [kind,name]=label.split(':');writeFileSync(join(root,'outputs',kind==='artifact'?'artifacts':'streams',name),raw);}
    // Poison forbidden names with unreadable links; the loader must never touch them.
    symlinkSync('/must-never-be-opened',join(root,'runtime_envelope_private'));symlinkSync('/must-never-be-opened',join(root,'result_image'));
    assert.deepEqual(loadRetainedStage(root,'base-1',o.publicInputsBytes),o);
    writeFileSync(join(root,'outputs/artifacts/extra'),Buffer.from('extra'));assert.throws(()=>loadRetainedStage(root,'base-1'),/membership/);rmSync(join(root,'outputs/artifacts/extra'));
    rmSync(join(root,'outputs/artifacts/checks-report'));symlinkSync(join(root,'receipt.json'),join(root,'outputs/artifacts/checks-report'));assert.throws(()=>loadRetainedStage(root,'base-1'));
    symlinkSync(root,join(root,'alias'));assert.throws(()=>readPublicFile(join(root,'alias/report.json')),/symlink/);
  }finally{rmSync(root,{recursive:true,force:true});}
}));

async function exerciseVerdictRoute(post,f,cert,setActive){
  assert.equal((await post(cert,f.token)).status,401);
  setActive({...f.input,originals:[f.input.originals[9]]});assert.equal((await post(cert)).status,400);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  setActive(f.input);assert.equal((await post(f.certificate(Buffer.from('six-check diagnostic')))).status,403);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  assert.equal((await post({...cert,verified:true})).status,400);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  const res=await post(cert);assert.equal(res.status,200);assert.equal((await res.json()).attempt.state,'verified');assert.equal(f.store.attempt(f.attemptId).reward_status,'unpaid');
}
test('HTTP handler cannot bypass complete-plan adapter with a signed diagnostic certificate',async()=>{
  const f=fixture(),a=adapter(f),result=a.evaluate(f.attemptId,f.input),cert=f.certificate(result.reportBytes);let active=f.input;
  const server=createAcceptanceApplication({...f,operatorToken:'operator-test-capability-1234567890',loadInput:async()=>active});
  try{
    const post=(body,token='operator-test-capability-1234567890')=>new Promise(resolve=>{
      const req=Readable.from([Buffer.from(JSON.stringify(body))]);Object.assign(req,{method:'POST',url:'/api/attempts/'+f.attemptId+'/verdict',headers:{'content-type':'application/json',authorization:'Bearer '+token}});
      let status;server.emit('request',req,{writeHead(code){status=code;},end(raw){resolve({status,json:async()=>JSON.parse(raw)});}});
    });
    await exerciseVerdictRoute(post,f,cert,v=>{active=v;});
  }finally{server.close();f.store.close();}
});

test('real loopback HTTP verdict walkthrough (requires local socket permission)',async t=>{
  const f=fixture(),a=adapter(f),result=a.evaluate(f.attemptId,f.input),cert=f.certificate(result.reportBytes);let active=f.input,calls=0;
  const server=createAcceptanceApplication({...f,operatorToken:'operator-test-capability-1234567890',loadInput:async()=>{calls++;return active;}});
  try{
    try{await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});}catch(error){if(['EPERM','EACCES'].includes(error.code)){t.skip('sandbox refuses loopback listen: '+error.code);return;}throw error;}
    const url='http://127.0.0.1:'+server.address().port+'/api/attempts/'+f.attemptId+'/verdict';
    const post=(body,token='operator-test-capability-1234567890')=>fetch(url,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify(body)});
    await exerciseVerdictRoute(post,f,cert,v=>{active=v;});assert.equal(calls,4);
  }finally{if(server.listening)await new Promise(resolve=>server.close(resolve));f.store.close();}
});

function changedReceipt(f,stage,mutate){
  const o=f.input.originals.find(x=>x.stage_id===stage),receipt=document(o.receiptBytes);mutate(receipt);o.receiptBytes=bytes(receipt);
  f.resignOriginal(stage,r=>{r.subject.receipt_sha256=sha(o.receiptBytes);r.subject.receipt_status=receipt.outputs.status;const body={attestation:null};for(const k of ['base_vm','base_vm_launch','harness_sha256','manifest_sha256','observed','outputs','run_id','runtime_inputs_commitment'])body[k]=receipt[k];r.subject.receipt_evidence_sha256=sha(bytes(['dsmack.receipt-evidence/4',body]));});
}
test('R1 same legitimate report authority cannot swap independently admitted native base or launch closure',()=>{
  for(const mutate of [r=>r.base_vm.os_image_hash='0'.repeat(64),r=>r.base_vm_launch.boot.kernel_sha256='0'.repeat(64),r=>r.base_vm_launch.admission.os_image_hash='0'.repeat(64),r=>r.base_vm_launch.boot.cmdline='other boot'])withFixture(f=>{
    changedReceipt(f,'candidate-1',mutate);assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/independently admitted native base_vm/);assert.equal(f.store.attempt(f.attemptId).state,'submitted');
  });
  for(const native of [undefined,null,{base_vm:null,base_vm_launch:{}},{base_vm:{},base_vm_launch:{}}])withFixture(f=>{f.admissions[f.attemptId].stages[0].native=native;assert.throws(()=>adapter(f));});
});
test('R5 signed completed/exit0 base with failing assertion checks cannot be relabelled as base failure',()=>withFixture(f=>{
  changedReceipt(f,'base-1',r=>{r.outputs.status='completed';r.outputs.exit_code=0;});
  assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/expected workload status/);
  const s=f.admissions[f.attemptId].stages[0];s.receipt_status='completed';s.exit_code=0;
  assert.throws(()=>adapter(f),/admitted classified driver outcome/);
}));
test('R7 exact admitted supported driver argv refuses cat, eval and ignored driver argument',()=>{
  const variants=[{entrypoint:['/usr/bin/cat'],command:['/workspace/inputs/trusted-driver']},{entrypoint:['/usr/bin/node'],command:['-e','0','/workspace/inputs/trusted-driver']},{entrypoint:['/usr/bin/node'],command:['/dev/null','/workspace/inputs/trusted-driver']}];
  for(const invocation of variants){
    const f=fixture({mutateManifest:(m,stage)=>{if(stage==='candidate-1'){const c=JSON.parse(m.docker_compose_file);Object.assign(c.services.driver,invocation);m.docker_compose_file=JSON.stringify(c);}}});
    try{
      assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/exact admitted driver argv/);
      f.admissions[f.attemptId].stages.find(s=>s.stage_id==='candidate-1').driver_execution=invocation;
      assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/unsupported admitted driver interpreter argv|supported admitted driver script argv required|admitted script is measured driver/);
    }finally{f.store.close();}
  }
});
test('R3 R6 generator broker-env declarations work with files-only projection and recorded-unchecked task3 receipt',()=>{
  const f=fixture({mutateManifest:(m,stage)=>{if(stage.startsWith('generate-')){m.allowed_envs=[{name:'ANTHROPIC_API_KEY',audience:'broker'}];m.required_envs=['ANTHROPIC_API_KEY'];}}});
  try{
    for(const stage of ['generate-1','generate-2','generate-3']){
      f.resignOriginal(stage,r=>{r.subject.commitment_status='recorded-unchecked';});
      const projection=document(f.input.originals.find(o=>o.stage_id===stage).publicInputsBytes);
      assert.deepEqual(Object.keys(projection).sort(),['commitments','files','manifest_sha256','runtime_input_version']);assert.equal(projection.env,undefined);
    }
    assert.doesNotThrow(()=>adapter(f).evaluate(f.attemptId,f.input));
    assert.equal(document(f.input.originals[6].reportBytes).subject.commitment_status,'recorded-unchecked');
    const o=f.input.originals[6],projection=document(o.publicInputsBytes);projection.env={ANTHROPIC_API_KEY:'SYNTHETIC-NONSECRET-REFUSAL-SENTINEL'};o.publicInputsBytes=bytes(projection);
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/unexpected or missing fields/);
  }finally{f.store.close();}
});
test('R3 unsupported broker-file variant refuses explicitly while workload env/browser env channels stay closed',()=>{
  for(const mode of ['broker-file','workload-env','browser-broker-env']){
    const f=fixture({mutateManifest:(m,stage)=>{
      if(mode==='broker-file'&&stage==='generate-1')m.allowed_files.push({slot:'broker-secret',target:'/broker/credential',audience:'broker',mode:'ro',required:true,max_bytes:1024});
      if(mode==='workload-env'&&stage==='generate-1')m.allowed_envs=[{name:'PUBLIC_MODE',audience:'workload'}];
      if(mode==='browser-broker-env'&&stage==='candidate-1')m.allowed_envs=[{name:'ANTHROPIC_API_KEY',audience:'broker'}];
    }});
    try{assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),mode==='broker-file'?/broker-file variant unsupported/:/only separately declared generator broker env supported/);}finally{f.store.close();}
  }
});
test('R6 generation specification text and SHA must be in the authorized stage profile',()=>{
  for(const specification of [null,{text:'SYNTHETIC spec',sha256:'0'.repeat(64)},{text:'',sha256:sha('')},{sha256:sha('spec')}]){
    const f=fixture({generationSpecification:specification});try{assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input));}finally{f.store.close();}
  }
});
test('R4 later CI admissions cannot be retroactively relinked to a replaced generation suite',()=>withFixture(f=>{
  const a=adapter(f);
  changedOutput(f,'generate-1',out=>{out['artifact:generated-suite']=bytes({schema:'dsmack-bounty-browser-suite/1',tests:[{id:'different-future-suite'}]});const checks=document(out['artifact:checks-report']);checks.suite_sha256=sha(out['artifact:generated-suite']);out['artifact:checks-report']=bytes(checks);});
  assert.throws(()=>a.evaluate(f.attemptId,f.input),/closed acceptance join refused/);
}));
test('R7 explicitly selected Python wrapper argv is supported without a shell fallback',()=>{
  const entrypoint=['/usr/bin/python3','-I','-B'];
  const f=fixture({mutateManifest:(m,stage)=>{if(stage.startsWith('generate-')){const c=JSON.parse(m.docker_compose_file);c.services.driver.entrypoint=entrypoint;m.docker_compose_file=JSON.stringify(c);}}});
  try{for(const s of f.admissions[f.attemptId].stages)if(s.stage_id.startsWith('generate-'))s.driver_execution.entrypoint=entrypoint;assert.doesNotThrow(()=>adapter(f).evaluate(f.attemptId,f.input));}finally{f.store.close();}
});
test('R6 no single packet or broker secret file can replace the agreed semantic public files',()=>{
  for(const slot of ['public-packet','broker-secret'])withFixture(f=>{
    const o=f.input.originals[6],projection=document(o.publicInputsBytes);projection.files=[{slot,content_base64:Buffer.from('SYNTHETIC nonsemantic packet').toString('base64')}];o.publicInputsBytes=bytes(projection);
    assert.throws(()=>adapter(f).evaluate(f.attemptId,f.input),/unique consumed file declaration/);
  });
});

// All original synthetic signatures and input commitments remain consistent;
// the cross-stage source relation itself must still reject these declarations.
test('authenticated transform declarations cannot replace actual full-source relation',()=>{
  for(const mutateTransform of [r=>r.changed_files=[],r=>r.allowed_paths.push('package.json'),r=>r.schema='dsmack-bounty-admission-transform/1']) {
    const f=fixture({mutateTransform});
    try {const adapter=new AcceptanceAdapter({store:f.store,admissions:f.admissions,reportKeys:f.reportKeys});
      assert.throws(()=>adapter.evaluate(f.attemptId,f.input));
    } finally {f.store.close();}
  }
});
