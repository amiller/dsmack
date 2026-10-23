// Independent operator admission mappings. No receipt/worker chooses a mode.
import { canonical, sha, exact, need } from '../bounty-demo/core.mjs';
export const D9_BASE='d9c169af135432e7e6c5309ac02f77f960254df8ce5b91cbd9a03c0b4af043b2';
export const B44_BASE='b44abf143bc7a4c6f3463bdda2c9fceefc8ec7bd63204de0a71ed714bdbbc143';
export const B44_RECEIPT_POLICY=Object.freeze({schema:'dsmack-native-receipt-run-id/1',mode:'b44-guest-selector-pid'});
export const ADMISSION2='dsmack-bounty-acceptance-admission/2';
export const D9_RECEIPT_POLICY=Object.freeze({schema:'dsmack-native-receipt-run-id/1',mode:'d9-guest-selector-pid'});
const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const equal=(a,b,label)=>need(canonical(a)===canonical(b),'binding mismatch: '+label);
// B44's independently reviewed derivation changes only broker watchdog constants
// and their source inventory row. The receipt producer is byte-identical to D9.
// Selection is operator-held: never infer a producer policy from returned bytes.
export function validateReceiptPolicy(policy,native){
 exact(policy,['schema','mode']);
 const selected=policy.mode===D9_RECEIPT_POLICY.mode?{policy:D9_RECEIPT_POLICY,base:D9_BASE}:
  policy.mode===B44_RECEIPT_POLICY.mode?{policy:B44_RECEIPT_POLICY,base:B44_BASE}:null;
 need(selected!==null,'closed selected receipt producer policy');equal(policy,selected.policy,'selected receipt producer policy');
 equal(native.base_vm.os_image_hash,selected.base,'known receipt producer base');
 equal(native.base_vm_launch.admission?.os_image_hash,selected.base,'known producer launch admission');
 return selected.base;
}
export function validateReceiptRunId(receipt,manifest,subject,pin,native){
 if(!Object.hasOwn(native,'receipt_run_id_policy')){equal(receipt.run_id,pin.run_id,'receipt run');return receipt.run_id;}
 const selectedBase=validateReceiptPolicy(native.receipt_run_id_policy,native);
 equal(manifest.name,subject.receipt_selector,'producer manifest selector');
 equal(manifest.base_vm?.os_image_hash,selectedBase,'producer manifest base');
 const prefix='guest-'+subject.receipt_selector+'-';
 need(typeof receipt.run_id==='string'&&receipt.run_id.length<=128&&receipt.run_id.startsWith(prefix),'native receipt selector prefix');
 const suffix=receipt.run_id.slice(prefix.length);
 // d9 Linux pid_max is bounded by PID_MAX_LIMIT (2^22). The PID is an
 // authenticated observation, never an application stage/assignment identity.
 need(/^[1-9][0-9]{0,6}$/.test(suffix)&&Number(suffix)<=4194304,'bounded positive native receipt PID');
 return receipt.run_id;
}
export function taskImageBinding(task,stages,primary){
 for(const s of stages)equal(s.native.base_vm.os_image_hash,task.image_sha256,'task base VM image');
 need(hash(primary.oci_manifest_sha256),'independent primary OCI');
 return {schema:'dsmack-task-image-binding/1',task_image_semantics:'base-vm-os-image',base_vm_os_image_sha256:task.image_sha256,primary_oci_manifest_sha256:primary.oci_manifest_sha256};
}
export function validateImageBinding(binding,task){
 exact(binding,['schema','task_image_semantics','base_vm_os_image_sha256','primary_oci_manifest_sha256']);
 equal(binding.schema,'dsmack-task-image-binding/1','task image mapping schema');equal(binding.task_image_semantics,'base-vm-os-image','task image semantics');
 equal(binding.base_vm_os_image_sha256,task.image_sha256,'task image base binding');need(hash(binding.primary_oci_manifest_sha256),'selected primary OCI mapping');return binding.primary_oci_manifest_sha256;
}
function rawDocument(value,cap,label){
 need(typeof value==='string'&&value.length>0&&value.length<=4*Math.ceil(cap/3),'bounded '+label);
 const bytes=Buffer.from(value,'base64');need(bytes.length>0&&bytes.length<=cap&&bytes.toString('base64')===value,'canonical base64 '+label);
 let v;try{v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{need(false,'invalid '+label);}
 need(Buffer.from(canonical(v)).equals(bytes),'canonical '+label+' bytes');return {value:v,bytes};
}
export function validateHarnessBinding(binding,task,expected,stages){
 exact(binding,['schema','harness_closure_b64','recipe_source_closure_b64','driver_source_paths']);equal(binding.schema,'dsmack-task-harness-binding/1','task harness semantics');
 const {value:h,bytes:hb}=rawDocument(binding.harness_closure_b64,65536,'harness closure');equal(sha(hb),task.harness_sha256,'task canonical harness closure');
 exact(h,['schema','platform','oci','drivers','cli','managed_settings_sha256','recipe_source_closure_sha256']);equal(h.schema,'dsmack-bounty-harness-closure/1','harness closure schema');equal(h.platform,'linux/arm64','harness platform');
 exact(h.oci,['generation_oci','browser_primary_oci','develop_oci']);for(const value of Object.values(h.oci))need(typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value),'harness OCI');
 exact(h.drivers,['applications/bounty-develop/driver.py','applications/bounty-runtime/driver.py']);for(const value of Object.values(h.drivers))need(hash(value),'harness driver hash');
 exact(h.cli,['version','sha256','requested_model']);need(typeof h.cli.version==='string'&&h.cli.version.length>0&&h.cli.version.length<=64&&hash(h.cli.sha256),'harness CLI identity');equal(h.cli.requested_model,expected.requested_model,'harness requested model');need(hash(h.managed_settings_sha256)&&hash(h.recipe_source_closure_sha256),'harness source/settings hashes');
 const {value:recipe,bytes:rb}=rawDocument(binding.recipe_source_closure_b64,4194304,'recipe source closure');equal(sha(rb),h.recipe_source_closure_sha256,'committed recipe source closure');exact(recipe,['schema','files']);equal(recipe.schema,'dsmack-requester-recipe-source-closure/1','recipe source schema');need(Array.isArray(recipe.files)&&recipe.files.length>0&&recipe.files.length<=10000,'recipe source inventory');
 const rows=new Map();let previous='';for(const row of recipe.files){exact(row,['path','bytes','sha256']);need(typeof row.path==='string'&&row.path.length<=512&&/^[A-Za-z0-9_.@+/-]+$/.test(row.path)&&row.path.split('/').every(p=>p&&p!=='.'&&p!=='..')&&row.path>previous,'recipe path order/identity');need(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=16777216&&hash(row.sha256),'recipe file identity');rows.set(row.path,row);previous=row.path;}
 exact(binding.driver_source_paths,['generate','base','candidate','primary-review']);
 for(let i=0;i<stages.length;i++){
  const pin=expected.stages[i],stage=stages[i],path=binding.driver_source_paths[pin.role];equal(path,'applications/bounty-runtime/driver.py','closed pilot role driver path');need(rows.has(path)&&Object.hasOwn(h.drivers,path),'selected role driver source');equal(rows.get(path).sha256,stage.driver_sha256,'role driver recipe member');
  equal(h.drivers[path],stage.driver_sha256,'role driver harness member');
  equal('sha256:'+pin.oci_manifest_sha256,h.oci[pin.role==='generate'?'generation_oci':'browser_primary_oci'],'role OCI harness member');
 }
 return {harness:h,recipe};
}
