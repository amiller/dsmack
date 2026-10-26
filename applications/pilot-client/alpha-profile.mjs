import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {canonical} from './alpha-release.mjs';
export const PROFILE_INSTANCES=Object.freeze({"bounty-board-search-generate-v1-judge1":{"selector":"bounty-board-search-generate-v1","role":"generate","judge_index":1},"bounty-board-search-generate-v1-judge2":{"selector":"bounty-board-search-generate-v1","role":"generate","judge_index":2},"bounty-board-search-generate-v1-judge3":{"selector":"bounty-board-search-generate-v1","role":"generate","judge_index":3},"bounty-board-search-browser-review-v1-suite1":{"selector":"bounty-board-search-browser-review-v1","role":"candidate","judge_index":1},"bounty-board-search-browser-review-v1-suite2":{"selector":"bounty-board-search-browser-review-v1","role":"candidate","judge_index":2},"bounty-board-search-browser-review-v1-suite3":{"selector":"bounty-board-search-browser-review-v1","role":"candidate","judge_index":3},"bounty-board-search-browser-review-v1-baseline1":{"selector":"bounty-board-search-browser-review-v1","role":"base","judge_index":1},"bounty-board-search-browser-review-v1-baseline2":{"selector":"bounty-board-search-browser-review-v1","role":"base","judge_index":2},"bounty-board-search-browser-review-v1-baseline3":{"selector":"bounty-board-search-browser-review-v1","role":"base","judge_index":3},"bounty-board-search-primary-review-v1-primary":{"selector":"bounty-board-search-primary-review-v1","role":"primary-review","judge_index":null}});
for(const value of Object.values(PROFILE_INSTANCES))Object.freeze(value);
export const ROLE_NAMES=['app_executable','app_info','coordinator','signing_policy','session_parser','approved_run','native_helper','alpha_signing_policy','helper_launcher','helper_gvproxy','kernel','initrd','system_disk','scratch_template','result_template','checksum_manifest','metadata','base_admission','compose_manifest','public_task','verifier_entrypoint','verifier_sources','verifier_environment','notary_evidence','alpha_entry','alpha_verifier','alpha_library','alpha_profile','installer'];
function need(ok,msg){if(!ok)throw Error(msg);}
function exact(o,list){need(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===[...list].sort().join('|'),'Profile fields');}
export function selectProfile(root,inventory,id){
 need(inventory.schema==='dsmack-alpha-release/2','Actual alpha requires inventory/2');
 need(new Set(inventory.profiles.map(p=>p.profile_id)).size===inventory.profiles.length&&new Set(inventory.profiles.map(p=>p.descriptor_path)).size===inventory.profiles.length,'Duplicate profile instance or descriptor');
 const descriptor=inventory.profiles.find(p=>p.profile_id===id);need(descriptor,'Profile not admitted');
 const raw=readFileSync(join(root,descriptor.descriptor_path));need(raw.length<=65536&&createHash('sha256').update(raw).digest('hex')===descriptor.descriptor_sha256,'Profile digest');
 const p=JSON.parse(raw.toString('utf8'));need(canonical(p)===raw.toString('utf8'),'Canonical profile');
 const developing=p.schema==='dsmack-alpha-profile/3';const diagnostic=id==='claude-broker-diagnostic-v1';const selector=PROFILE_INSTANCES[id]?.selector??id;
 exact(p,['schema','profile_id','execution_profile','selected_image','image','app_bundle','roles',...(developing?['private_input_policy']:[])]);
 need((developing||p.schema==='dsmack-alpha-profile/2')&&p.profile_id===id,'Profile identity');
 if(developing){exact(p.private_input_policy,['schema','channel','max_bytes','public_runtime_envelope']);const policy=p.private_input_policy;need(policy.schema==='dsmack-alpha-private-channel/1'&&policy.channel==='runtime-envelope-v1'&&policy.max_bytes===1073741824&&policy.public_runtime_envelope===false,'Private channel policy');}
 exact(p.roles,ROLE_NAMES);const used=new Set();for(const role of ROLE_NAMES){const path=p.roles[role];need(typeof path==='string'&&inventory.files.some(f=>f.path===path),'Role not in inventory');need(!used.has(path),'Aliased role');used.add(path);}
 need(typeof p.app_bundle==='string'&&!p.app_bundle.startsWith('/')&&p.app_bundle.split('/').every(x=>x&&x!=='.'&&x!=='..')&&!p.app_bundle.includes('\\'),'App bundle path');
 need(p.roles.app_info===p.app_bundle+'/Contents/Info.plist'&&p.roles.app_executable.startsWith(p.app_bundle+'/Contents/MacOS/')&&!p.roles.app_executable.slice((p.app_bundle+'/Contents/MacOS/').length).includes('/'),'Bundle roles');
 const q=p.execution_profile;exact(q,['schema','profile_id','workload_id','resource_profile','memory_mib','vcpus','runtime_seconds','scratch_template_bytes','result_template_bytes','compose_manifest_sha256','model_profile','security_preset']);
 need(q.schema==='dsmack-protected-execution-profile/1'&&(developing?['bounty-board-search-develop-v1','bounty-board-search-generate-v1','claude-broker-diagnostic-v1','agent-turns-edit-v1'].includes(selector):['bounty-board-search-browser-review-v1','bounty-board-search-primary-review-v1'].includes(selector))&&q.profile_id===selector&&q.workload_id===selector,'Initial browser scope');
 for(const [k,v] of Object.entries({resource_profile:'mini-4096',memory_mib:4096,vcpus:1,runtime_seconds:600,scratch_template_bytes:4294967296,result_template_bytes:268435456,model_profile:developing&&!diagnostic?'claude-opus-4-8':'none',security_preset:developing?'none':'browser-sandbox-v1'}))need(q[k]===v,'Unqualified profile '+k);
 const file=role=>inventory.files.find(f=>f.path===p.roles[role]);
 need(file('scratch_template').bytes===q.scratch_template_bytes&&file('result_template').bytes===q.result_template_bytes&&file('compose_manifest').sha256===q.compose_manifest_sha256,'Profile resource pins');
 need(/^[a-f0-9]{64}$/.test(p.selected_image)&&file('checksum_manifest').sha256===p.selected_image,'Selected base');
 exact(p.image,['root_hash','rootfs_size','kernel_cmdline']);need(/^[a-f0-9]{64}$/.test(p.image.root_hash)&&Number.isSafeInteger(p.image.rootfs_size)&&p.image.rootfs_size>0&&p.image.rootfs_size<=file('system_disk').bytes&&typeof p.image.kernel_cmdline==='string'&&p.image.kernel_cmdline.length<=8192&&!p.image.kernel_cmdline.includes('\0'),'Image descriptors');
 need(file('notary_evidence').sha256===inventory.app.notarization_evidence_sha256,'Notary evidence binding');
 return p;
}
