// SYNTHETIC CONTROL ONLY. Ephemeral fake report authority; NO Apple assertions,
// VM execution, original diagnostic, real acceptance, payment or deployed keys.
import { generateKeyPairSync, sign } from 'node:crypto';
import { Store, sha } from '../bounty-demo/core.mjs';
import { encoded as bytes } from './original-report.mjs';
import { treeIdentity } from './projection.mjs';
import { D9_BASE, B44_BASE, ADMISSION2, D9_RECEIPT_POLICY, B44_RECEIPT_POLICY } from './admission-identities.mjs';
import { OUTPUT_BUNDLE } from './output-bundle.mjs';
export function syntheticTar(entries){
  const parts=[];
  for(const {path,mode,data,type=48} of entries){
    const h=Buffer.alloc(512);h.write(path,0,100,'ascii');
    const oct=(n,start,len)=>h.write(n.toString(8).padStart(len-1,'0')+'\0',start,len,'ascii');
    oct(mode,100,8);oct(0,108,8);oct(0,116,8);oct(data.length,124,12);oct(0,136,12);h.fill(32,148,156);h[156]=type;h.write('ustar\0'+'00',257,8,'ascii');
    const checksum=h.reduce((a,b)=>a+b,0);h.write(checksum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');
    parts.push(h,data,Buffer.alloc((512-data.length%512)%512));
  }
  return Buffer.concat([...parts,Buffer.alloc(1024)]);
}
export function syntheticResultTar(files){
 const all={...files,'output-manifest.json':bytes({schema:'dsmack-bounty-output-manifest/1',files:Object.keys(files).sort().map(name=>({name,size:files[name].length,sha256:sha(files[name])}))})};
 const entries=Object.keys(all).sort().map(path=>({path,mode:420,data:all[path]}));const raw=syntheticTar(entries);let offset=0;
 for(const entry of entries){const h=raw.subarray(offset,offset+512);for(const [start,len] of [[108,8],[116,8],[136,12],[329,8],[337,8]])h.write('0'.repeat(len-1)+'\0',start,len,'ascii');h.fill(32,148,156);h.write(h.reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');offset+=512+Math.ceil(entry.data.length/512)*512;}
 return raw;
}
const h=x=>sha(x),pinKeys=['stage_id','role','judge_index','run_id','request_sha256','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256'];
export function syntheticAdapterFixture({dbPath=':memory:',clock=()=>1000,mutateManifest=()=>{},mutateTransform=()=>{},bundledOutputs=false,modernAdmission=false,modernBase=D9_BASE,generationSpecification={text:'SYNTHETIC pinned specification',sha256:sha('SYNTHETIC pinned specification')}}={}){
  if(modernAdmission&&![D9_BASE,B44_BASE].includes(modernBase))throw Error('synthetic closed modern base');
  const modernPolicy=modernBase===B44_BASE?B44_RECEIPT_POLICY:D9_RECEIPT_POLICY;
  const appKeys=generateKeyPairSync('ed25519'),originalKeys=generateKeyPairSync('ed25519');
  const appKey=appKeys.publicKey.export({format:'pem',type:'spki'});
  const reportKeys={'synthetic-original':originalKeys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
  const store=new Store(dbPath,{now:clock,verifierKeys:{'synthetic-application':appKey}});
  const driverBytes=Buffer.from('SYNTHETIC admitted driver');
  const recipeBytes=bytes({schema:'dsmack-requester-recipe-source-closure/1',files:[{path:'applications/bounty-runtime/driver.py',bytes:driverBytes.length,sha256:sha(driverBytes)}]});
  const harnessBytes=bytes({schema:'dsmack-bounty-harness-closure/1',platform:'linux/arm64',oci:{generation_oci:'sha256:'+h('generator-image'),browser_primary_oci:'sha256:'+h('browser-image'),develop_oci:'sha256:'+h('develop-image')},drivers:{'applications/bounty-develop/driver.py':h('develop-driver'),'applications/bounty-runtime/driver.py':sha(driverBytes)},cli:{version:'synthetic',sha256:h('cli'),requested_model:'SYNTHETIC-explicit-model'},managed_settings_sha256:h('settings'),recipe_source_closure_sha256:sha(recipeBytes)});
  const taskTerms={id:'board-search',repo:'amiller/bounty-arcade',issue_number:1,title:'SYNTHETIC ADAPTER CONTROL',base_commit:'b'.repeat(40),checker_sha256:h('complete-policy'),image_sha256:modernAdmission?modernBase:h('browser-image'),harness_sha256:modernAdmission?sha(harnessBytes):h('native-harness'),reward:{amount:'1',asset:'ETH',chain:'unfunded synthetic'}};const t=store.createTask(taskTerms);
  const {attempt:a,token}=store.claim(t.id,{worker:'synthetic Mac operator',payee:'0x'+'2'.repeat(40)});
  const data=Buffer.from('SYNTHETIC candidate source\n'),candidateManifestBytes=bytes([{path:'apps/board/logic.js',mode:420,bytes:data.length,sha256:sha(data)}]),candidate=treeIdentity(candidateManifestBytes),bundleBytes=syntheticTar([{path:'apps/board/logic.js',mode:420,data}]);
  const baseData=Buffer.from('SYNTHETIC base source'),baseManifestBytes=bytes([{path:'apps/board/logic.js',mode:420,bytes:baseData.length,sha256:sha(baseData)}]),baseBundle=syntheticTar([{path:'apps/board/logic.js',mode:420,data:baseData}]),base=treeIdentity(baseManifestBytes);
  store.submit(a.id,{candidate_sha256:candidate,bundle_sha256:sha(bundleBytes)});
  const transformRecord={schema:'dsmack-bounty-admission-transform/2',operation:'allowlisted-existing-file-replacement',base_tree_manifest_sha256:base,candidate_tree_manifest_sha256:candidate,allowed_paths:['apps/board/index.html','apps/board/logic.js','apps/board/ui.js'],changed_files:['apps/board/logic.js']};
  mutateTransform(transformRecord);
  const transformHash=sha(bytes(transformRecord));
  const request={schema:'dsmack-bounty-public-request/1',task_id:t.id,task_terms_sha256:t.terms_sha256,attempt_id:a.id,attempt_nonce:a.nonce,run_id:'primary-review-run',run_role:'review',acceptance_profile_sha256:t.checker_sha256,base:{repo:'https://github.com/'+t.repo,commit:t.base_commit,tree_manifest_sha256:base},candidate:{upstream_commit:null,tree_manifest_sha256:candidate,admission_transform_sha256:transformHash},toolchain:{platform:'linux/arm64',image_digest:'sha256:'+h('browser-image')},required_artifacts:bundledOutputs?['public-input-audit','result-files','stage-checks']:['source-bundle']};
  const requestBytes=bytes(request),primaryHash=sha(Buffer.concat([Buffer.from(request.schema+'\0'),requestBytes]));
  const expected={plan_sha256:h('plan'),primary_request_sha256:primaryHash,task_terms_sha256:t.terms_sha256,attempt_id:a.id,attempt_nonce:a.nonce,base_tree_sha256:base,candidate_tree_sha256:candidate,requested_model:'SYNTHETIC-explicit-model',stages:[]};
  const result={...expected,schema:'dsmack-bounty-stage-results/1',stages:[]};delete result.requested_model;
  const admission={task:{task_id:t.id,terms_sha256:t.terms_sha256,checker_sha256:t.checker_sha256,image_sha256:t.image_sha256,harness_sha256:t.harness_sha256,attempt_id:a.id,nonce:a.nonce,payee:a.payee,candidate_sha256:candidate,bundle_sha256:sha(bundleBytes)},expected,stages:[],delivery:{bundle_artifact:'source-bundle',candidate_manifest_artifact:'source-manifest'}};
  if(modernAdmission)Object.assign(admission,{schema:ADMISSION2,task_image_semantics:'base-vm-os-image',harness_binding:{schema:'dsmack-task-harness-binding/1',harness_closure_b64:harnessBytes.toString('base64'),recipe_source_closure_b64:recipeBytes.toString('base64'),driver_source_paths:Object.fromEntries(['generate','base','candidate','primary-review'].map(role=>[role,'applications/bounty-runtime/driver.py']))}});
  const originals=[];
  const stages=['base-1','base-2','base-3','candidate-1','candidate-2','candidate-3','generate-1','generate-2','generate-3','primary-review'];
  for(const stage of stages){
    const role=stage==='primary-review'?stage:stage.split('-')[0],i=role==='primary-review'?null:Number(stage.at(-1));
    const stageProfileBytes=role==='generate'?bytes({schema:'dsmack-bounty-generation-stage-profile/1',specification:generationSpecification}):role==='primary-review'?bytes({admission_transform:{record:transformRecord,sha256:transformHash}}):Buffer.from(role+'-profile');
    const pin={stage_id:stage,role,judge_index:i,run_id:stage+'-run',request_sha256:role==='primary-review'?primaryHash:h(stage+'-request'),stage_profile_sha256:sha(stageProfileBytes),oci_manifest_sha256:h(role==='generate'?'generator-image':'browser-image'),source_tree_sha256:['generate','base'].includes(role)?base:candidate};
    expected.stages.push(pin);
    const suite=bytes({schema:'dsmack-bounty-browser-suite/1',tests:[{id:'judge-'+i+'-assertion'}]});
    let checks,files={};
    if(role==='generate') {files['suite.json']=suite;checks={schema:'dsmack-bounty-generation-checks/1',completed:true,requested_model:expected.requested_model,observed_model:expected.requested_model,suite_sha256:sha(suite),base_tree_sha256:base};}
    else if(role==='primary-review') {checks={schema:'dsmack-bounty-primary-checks/1',fixed_browser_baselines:[true,true,true,true],fixed_logic_baselines:[true,true,true,true],feature_checks:[true,true,true,true,true,true]};files['source-bundle']=bundleBytes;files['source-manifest']=candidateManifestBytes;}
    else checks={schema:'dsmack-bounty-ci-checks/1',browser_started:true,completed:true,infrastructure_failed:false,tests:[{id:'judge-'+i+'-assertion',status:role==='base'?'assertion_failed':'passed'}],suite_sha256:sha(suite)};
    files['checks.json']=bytes(checks);
    if(role==='primary-review')for(const name of ['browser-trace','browser-screenshot','browser-video'])files[name]=Buffer.from('SYNTHETIC media bytes for '+name+'; no actual browser execution');
    if(bundledOutputs)files['public-input-audit.json']=Buffer.from('SYNTHETIC observation; never input authority');
    const mapping=Object.fromEntries(Object.keys(files).sort().map(name=>[name,bundledOutputs?name:name==='checks.json'?'checks-report':name==='suite.json'?'generated-suite':name]));
    const nativeFiles=bundledOutputs?{'result-files':syntheticResultTar(files),'stage-checks':files['checks.json'],'public-input-audit':files['public-input-audit.json']}:Object.fromEntries(Object.entries(files).map(([name,b])=>[mapping[name],b]));
    const outputs={...Object.fromEntries(Object.entries(nativeFiles).map(([name,b])=>['artifact:'+name,b])),'stream:stdout':Buffer.from('SYNTHETIC stdout cannot grade'),'stream:stderr':Buffer.alloc(0)};
    const input_slots={request:'stage-request',task_terms:'task-terms',acceptance_profile:'acceptance-profile',plan:'stage-plan',stage_profile:'stage-profile',driver:'trusted-driver',source_manifest:'source-manifest',source_bundle:'source-bundle',suite:['base','candidate'].includes(role)?'input-suite':null};
    const driver=driverBytes;
    const childRequest={schema:'dsmack-bounty-child-request/1',task_id:t.id,task_terms_sha256:t.terms_sha256,acceptance_profile_sha256:t.checker_sha256,plan_sha256:expected.plan_sha256,attempt_id:a.id,attempt_nonce:a.nonce,payee:a.payee,requested_model:expected.requested_model,input_suite_sha256:['base','candidate'].includes(role)?sha(suite):null};
    for(const k of ['run_id','stage_id','role','judge_index','stage_profile_sha256','oci_manifest_sha256','source_tree_sha256'])childRequest[k]=pin[k];
    const stageRequest=role==='primary-review'?requestBytes:bytes(childRequest);
    if(role!=='primary-review')pin.request_sha256=sha(Buffer.concat([Buffer.from(childRequest.schema+'\0'),stageRequest]));
    const publicFiles={'stage-request':stageRequest,'task-terms':bytes(taskTerms),'acceptance-profile':Buffer.from('complete-policy'),'stage-plan':Buffer.from('plan'),'stage-profile':stageProfileBytes,'trusted-driver':driver,'source-manifest':['generate','base'].includes(role)?baseManifestBytes:candidateManifestBytes,'source-bundle':['generate','base'].includes(role)?baseBundle:bundleBytes};
    if(['base','candidate'].includes(role))publicFiles['input-suite']=suite;
    const driver_execution={entrypoint:['/usr/bin/node'],command:['/workspace/inputs/trusted-driver']};
    const native={base_vm:{architecture:'aarch64',os_image_hash:modernAdmission?modernBase:h('admitted-base')},base_vm_launch:{admission:{decision:'admitted',os_image_hash:modernAdmission?modernBase:h('admitted-base')},boot:{kernel_sha256:h('admitted-kernel'),initrd_sha256:h('admitted-initrd'),cmdline:'SYNTHETIC admitted boot'}}};
    const manifest={allowed_envs:[],required_envs:[],image_platform:{os:'linux',architecture:'arm64'},docker_compose_file:JSON.stringify({services:{driver:{image:'local@sha256:'+pin.oci_manifest_sha256,...JSON.parse(bytes(driver_execution)),volumes:Object.keys(publicFiles).sort().map(slot=>slot+':/workspace/inputs/'+slot+':ro')}}}),harness:{sha256:h('native-harness')},allowed_files:Object.keys(publicFiles).sort().map(slot=>({slot,target:'/workspace/inputs/'+slot,audience:'workload',required:true,mode:'ro',max_bytes:16*1024*1024}))};
    if(modernAdmission)Object.assign(manifest,{name:stage,base_vm:native.base_vm});
    mutateManifest(manifest,stage);
    const manifestBytes=bytes(manifest),manifestHash=sha(manifestBytes),inputFiles=Object.keys(publicFiles).sort().map(slot=>({slot,content_base64:publicFiles[slot].toString('base64')}));
    const scope={include:['files'],file_slots:Object.keys(publicFiles).sort()};
    const input_commitment={alg:'dsmack.task-commitment/3',scope,inputs_sha256:sha(bytes(['dsmack.task-commitment/3',manifestHash,scope,{files:inputFiles}]))};
    const publicInputsBytes=bytes({runtime_input_version:4,manifest_sha256:manifestHash,files:inputFiles,commitments:input_commitment});
    const receipt={environment:'vm',manifest_sha256:manifestHash,run_id:modernAdmission?'guest-'+stage+'-1':pin.run_id,harness_sha256:h('native-harness'),...JSON.parse(bytes(native)),observed:{},runtime_inputs_commitment:input_commitment,outputs:{status:role==='base'?'failed':'completed',exit_code:role==='base'?1:0,stdout:{bytes:outputs['stream:stdout'].length,sha256:sha(outputs['stream:stdout'])},stderr:{bytes:0,sha256:sha(Buffer.alloc(0))},artifacts:Object.entries(nativeFiles).sort(([a],[b])=>a.localeCompare(b)).map(([name,b])=>({name,bytes:b.length,sha256:sha(b)})),missing:[],started_unix_s:900,ended_unix_s:950,cancel:null}};
    const receiptBytes=bytes(receipt),receiptBody={attestation:null};for(const k of ['base_vm','base_vm_launch','harness_sha256','manifest_sha256','observed','outputs','run_id','runtime_inputs_commitment'])receiptBody[k]=receipt[k];
    const context={verifier:{id:'dsmack-runresult-verifier',version:'2',key_id:'synthetic-original'},verifier_context:{core_sha256:h('core'),extractor_tool_sha256:h('extractor'),extraction_contract:'dsmack.safe-extract-result/1',enrollment_sha256:h('enrollment')},subject:{manifest_sha256:manifestHash,receipt_selector:stage,challenge:'SYNTHETIC-'+a.nonce+'-'+stage,key_id_b64:Buffer.alloc(32,1).toString('base64'),receipt_environment:'vm'}};
    const report={runresult_report_version:2,verifier:context.verifier,verifier_context:context.verifier_context,verified:true,subject:{...context.subject,launch_evidence_sha256:h(stage+'-launch'),envelope_sha256:h(stage+'-envelope'),pair_evidence_sha256:h(stage+'-pair'),launch_counter:1,result_counter:2,result_image_sha256:h(stage+'-image'),result_image_bytes:512,console_sha256:h(stage+'-console'),console_bytes:0,receipt_path:stage+'/receipt.json',receipt_sha256:sha(receiptBytes),receipt_evidence_sha256:sha(bytes(['dsmack.receipt-evidence/4',receiptBody])),export_index_sha256:h(stage+'-index'),receipt_status:receipt.outputs.status,outputs_verified:true,commitment_status:'bound-to-validated-envelope',evidence_class:'apple-hardware-assertion'},apple:{assertion_counters_authenticated:true,receipt_status:'retained_not_validated',environment:'production',verified_at_unix_s:990}};
    report.report_sig={alg:'ed25519',key_id:'synthetic-original',sig_b64:sign(null,bytes(report),originalKeys.privateKey).toString('base64')};
    const original={stage_id:stage,reportBytes:bytes(report),receiptBytes,manifestBytes,publicInputsBytes,outputs};originals.push(original);
    admission.stages.push({stage_id:stage,context,input_commitment,files:mapping,receipt_status:receipt.outputs.status,exit_code:receipt.outputs.exit_code,input_slots,driver_sha256:sha(driver),driver_execution,native:modernAdmission?{...native,receipt_run_id_policy:{...modernPolicy}}:native,output_bundle:bundledOutputs?JSON.parse(JSON.stringify(OUTPUT_BUNDLE)):null});
    result.stages.push({...Object.fromEntries(pinKeys.map(k=>[k,pin[k]])),input_suite_sha256:['base','candidate'].includes(role)?sha(suite):null,output_manifest_sha256:sha(bytes({schema:'dsmack-bounty-output-manifest/1',files:Object.keys(files).sort().map(name=>({name,size:files[name].length,sha256:sha(files[name])}))})),execution_evidence_sha256:sha(original.reportBytes),checks_sha256:sha(files['checks.json']),status:role==='base'?'assertion_failed':'completed'});
  }
  const input={requestBytes,resultsBytes:bytes(result),originals};
  function certificate(reportBytes,overrides={}){const payload={schema:'dsmack-bounty-verdict/1',task_id:t.id,terms_sha256:t.terms_sha256,attempt_id:a.id,nonce:a.nonce,payee:a.payee,candidate_sha256:candidate,bundle_sha256:sha(bundleBytes),checker_sha256:t.checker_sha256,image_sha256:t.image_sha256,harness_sha256:t.harness_sha256,report_sha256:sha(reportBytes),accepted:true,checks:{apple:true,outputs:true,functional:true},issued_at:1000,expires_at:1200,...overrides};return {key_id:'synthetic-application',payload,signature:sign(null,bytes(payload),appKeys.privateKey).toString('base64')};}
  function resignOriginal(stageId,change){const original=originals.find(x=>x.stage_id===stageId),report=JSON.parse(original.reportBytes);delete report.report_sig;change(report,original);report.report_sig={alg:'ed25519',key_id:'synthetic-original',sig_b64:sign(null,bytes(report),originalKeys.privateKey).toString('base64')};original.reportBytes=bytes(report);result.stages.find(x=>x.stage_id===stageId).execution_evidence_sha256=sha(original.reportBytes);input.resultsBytes=bytes(result);}
  return {store,appKey,clock,attemptId:a.id,token,task:t,admissions:{[a.id]:admission},reportKeys,input,result,certificate,resignOriginal};
}
