import {DatabaseSync} from 'node:sqlite';
import {readFileSync,lstatSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=v=>typeof v==='string'&&/^(?:0x)?[a-f0-9]{64}$/.test(v)?v.replace(/^0x/,''):null;
const id=v=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v)?v:null;
const text=(v,n=240)=>typeof v==='string'&&v.length<=n&&!/[\x00-\x1f\x7f]/.test(v)?v:null;
const number=v=>Number.isSafeInteger(v)&&v>=0?v:null;
const bool=v=>typeof v==='boolean'?v:null;
const repo=v=>typeof v==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(v)?v:null;
const address=v=>typeof v==='string'&&/^0x[a-fA-F0-9]{40}$/.test(v)?v.toLowerCase():null;
const commit=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v)?v:null;
const states=new Set(['registered','queued','preparing','prepared','verifying','verified','failed','verification_error','preparation_error','preparation_failed','execution_error','claim_uncertain','claim_failed','claimed','running','submitted','rejected','settled','expired']);
function taskKey(t){if(!t||!/^\d+$/.test(String(t.task_id))||!address(t.contract)||!/^\d+$/.test(String(t.chain_id)))return null;return `${t.chain_id}:${address(t.contract)}:${t.task_id}`;}
function publicBase(c){try{const u=new URL(c.public_base_url);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)return null;return u.href.replace(/\/$/,'');}catch{return null;}}
function safeURL(value,c){try{const base=publicBase(c);if(!base)return null;const u=new URL(value);if(u.username||u.password||u.search||u.hash||!u.href.startsWith(base+'/api/artifacts/'))return null;const tail=u.href.slice((base+'/api/artifacts/').length);return /^[a-f0-9]{32}\/[A-Za-z0-9._-]{1,100}$/.test(tail)?u.href:null;}catch{return null;}}
function artifact(f,c){if(!f||typeof f.name!=='string'||!/^[A-Za-z0-9._-]{1,100}$/.test(f.name)||number(f.bytes)===null||!hash(f.sha256))return null;const out={name:f.name,bytes:f.bytes,sha256:hash(f.sha256),visibility:'metadata_only'};const url=safeURL(f.url,c);if(url){out.url=url;out.visibility='public';}return out;}
function metadata(t,key,c){return {task_key:key,title:c.funded===false?'Unfunded rehearsal':text(t?.title),issue_url:repo(t?.repository??t?.repo)&&number(t?.issue_number)?`https://github.com/${t.repository??t.repo}/issues/${t.issue_number}`:null,repository:repo(t?.repository??t?.repo),source_id:c.id};}
function mapping(t,c){const matches=(c.task_mappings??[]).filter(m=>hash(m.package_hash)&&hash(m.package_hash)===hash(t?.terms_sha256));return matches.length===1?matches[0]:null;}
function source(c,now){return {id:text(c.id,100)??'invalid-source',kind:'arcade-pilot',status:'ok',observed_at:now,latest_record_created_at:null,scope:{task_key:c.funded===false?null:taskKey(c.task),artifact_metadata:'declared evidence files; upload bytes are received bytes'},attempt_count:0,invalid_record_count:0};}
export function projectArcadeRows(rows,c,{now=Math.floor(Date.now()/1000),deadlineByAttempt={}}={}){
 const s=source(c,now),attempts=[],submissions=new Map();
 for(const row of rows){if(row.kind!=='submission')continue;const v=row.body;if(!v||!id(v.attempt_id)||!Array.isArray(v.files))continue;const list=submissions.get(v.attempt_id)??[];list.push(v);submissions.set(v.attempt_id,list);}
 for(const row of rows){if(row.kind!=='attempt')continue;const a=row.body;if(!a||!id(a.id)){s.invalid_record_count++;continue;}
  const files=(submissions.get(a.id)??[]).flatMap(v=>v.files).map(f=>({raw:f,public:artifact(f,c)})).filter(f=>f.public);
  const unique=new Map(files.map(f=>[`${f.public.name}:${f.public.sha256}`,f]));const selected=[...unique.values()];const received=selected.map(f=>Math.min(number(f.raw.offset)??0,f.public.bytes));
  const reported=states.has(a.state)?a.state:'unknown';const deadline=deadlineByAttempt[a.id]??null;const expired=deadline?Date.parse(deadline)<now*1000:null;const attention=expired&&['prepared','queued'].includes(reported);
  const t=c.task??{};const inputFiles=(a.execution?.artifacts??[]).map(f=>{const d=artifact(f,c);if(!d)return null;const url=safeURL(f.url,c);const jid=url?new URL(url).pathname.split('/').at(-2):null;const held=rows.find(r=>r.kind==='artifacts'&&r.id===jid)?.body?.files?.find(v=>v.name===f.name&&v.bytes===f.bytes&&v.sha256===f.sha256);return {descriptor:{...d,category:'input'},received:held?Math.min(number(held.offset)??0,d.bytes):null};}).filter(Boolean);const matching=!t.slug||a.task_slug===t.slug;const key=matching&&c.funded!==false?taskKey(t):null;const verdict=a.verdict??{};
  const out={id:a.id,source_id:c.id,historical:false,task_key:key,repository:repo(t.repository),candidate_commit:commit(a.candidate_commit),payee:address(a.payee),execution_mode:['self','best_effort'].includes(a.execution_mode)?a.execution_mode:null,state:attention?'needs_attention':reported,reported_state:reported,created_at:number(a.created_at),verification:{accepted:bool(verdict.accepted),level:['full','partial'].includes(verdict.verification_level)?verdict.verification_level:null,apple_verified:bool(verdict.apple_verified),functional_pass:bool(verdict.functional_pass??verdict.functional_passed),functional_check_sha256:hash(verdict.report_sha256)},upload:{file_count:selected.length||null,bytes:selected.length?received.reduce((a,b)=>a+b,0):null,complete:selected.length?selected.every((f,i)=>received[i]===f.public.bytes):null},inputs:{file_count:inputFiles.length||null,bytes:inputFiles.length&&inputFiles.every(f=>f.received!==null)?inputFiles.reduce((n,f)=>n+f.received,0):null,complete:inputFiles.length&&inputFiles.every(f=>f.received!==null)?inputFiles.every(f=>f.received===f.descriptor.bytes):null},artifacts:[...inputFiles.map(f=>f.descriptor),...selected.map(f=>({...f.public,category:'evidence'}))],source_url:publicBase(c)?`${publicBase(c)}/api/attempts/${a.id}`:null,error_code:attention?'prepared_deadline_expired':reported==='unknown'?'unrecognized_state':null,deadline:{expires_at:deadline,expired}};
  // A claim's actual assignment ID is explicit evidence; never copy task ID into it.
  const assignment=a.claim?.assignment_id;if(/^\d+$/.test(String(assignment)))out.assignment_id=String(assignment);
  const updated=number(a.updated_at??a.verdict?.verified_at_unix_s);if(updated!==null)out.updated_at=updated;attempts.push(out);if(out.created_at!==null)s.latest_record_created_at=Math.max(s.latest_record_created_at??0,out.created_at);
  if(!key&&c.funded!==false){s.status='partial';s.error_code='task_mapping_unavailable';}
 }
 s.attempt_count=attempts.length;if(s.invalid_record_count){s.status='partial';s.error_code='invalid_records';}
 return {attempts,sources:[s],task_metadata:[metadata(c.task,c.funded===false?null:taskKey(c.task),c)]};
}
function verifiedDeadline(a,records,c){
 const d=a.execution?.artifacts?.find(d=>d.name==='workload-admission.json');const url=safeURL(d?.url,c);if(!d||!url)return null;
 const jid=new URL(url).pathname.split('/').at(-2);const store=records.find(r=>r.kind==='artifacts'&&r.id===jid)?.body;const held=store?.files?.find(f=>f.name==='workload-admission.json');if(!held||held.offset!==held.bytes||held.bytes!==d.bytes||held.sha256!==d.sha256||held.bytes>65536)return null;
 const parent=join(c.artifact_root??dirname(c.db_path),'artifact-'+jid);const file=join(parent,'workload-admission.json');if(lstatSync(parent).isSymbolicLink())return null;const st=lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size!==d.bytes)return null;
 const raw=readFileSync(file);if(sha(raw)!==d.sha256)return null;const v=JSON.parse(raw);return typeof v.expires_at==='string'&&Number.isFinite(Date.parse(v.expires_at))?v.expires_at:null;
}
function readRows(db){return db.prepare("SELECT kind,id,body FROM records WHERE kind IN ('attempt','submission','artifacts') OR (kind='config' AND id='task') ORDER BY kind,id").all().map(r=>({kind:r.kind,id:r.id,body:JSON.parse(r.body)}));}
function errorFeed(c,kind,code,now){return {attempts:[],sources:[{id:text(c.id,100)??'invalid-source',kind,status:'error',error_code:code,observed_at:now,latest_record_created_at:null,scope:{task_key:c.funded===false?null:taskKey(c.task)},attempt_count:null}],task_metadata:[]};}
export function readArcadeSource(c,{now=Math.floor(Date.now()/1000)}={}){
 let db;try{db=new DatabaseSync(c.db_path,{readOnly:true});db.exec('PRAGMA query_only=ON; BEGIN');const rows=readRows(db),deadlines={};const stored=rows.find(r=>r.kind==='config'&&r.id==='task')?.body;if(!c.task&&stored)c={...c,task:{task_id:stored.task_id,chain_id:stored.chain_id,contract:stored.contract,slug:stored.slug,repository:stored.repository,title:stored.title,issue_number:stored.issue_number}};let unavailable=0;
  for(const r of rows.filter(r=>r.kind==='attempt')){try{const d=verifiedDeadline(r.body,rows,c);if(d)deadlines[r.body.id]=d;}catch{unavailable++;}}
  const out=projectArcadeRows(rows,c,{now,deadlineByAttempt:deadlines});if(unavailable){out.sources[0].status='partial';out.sources[0].error_code='deadline_artifact_unavailable';}db.exec('ROLLBACK');return out;
 }catch{return errorFeed(c,'arcade-pilot','source_unavailable_or_invalid',now);}finally{db?.close();}
}
export function projectLegacyRows(tasks,rows,c,{now=Math.floor(Date.now()/1000)}={}){
 const attempts=[],task_metadata=[],s=source(c,now);s.kind='bounty-demo';s.scope={artifact_metadata:'legacy Store records submission hashes only; byte counts unavailable',state_semantics:'reported historical state, not current native liveness'};const byId=new Map(tasks.map(t=>[t.id,t]));
 for(const t of tasks){const m=mapping(t,c);task_metadata.push(metadata(t,taskKey(m),c));}
 for(const a of rows){if(!id(a.id)){s.invalid_record_count++;continue;}const t=byId.get(a.task_id),m=mapping(t,c);const key=taskKey(m),v=a.verdict?.payload??{},checks=v.checks??{};const artifacts=[];if(hash(a.submission?.bundle_sha256))artifacts.push({name:'submitted-bundle',bytes:null,sha256:hash(a.submission.bundle_sha256),category:'evidence',visibility:'metadata_only'});
  const out={id:a.id,source_id:c.id,historical:true,task_key:key,repository:repo(t?.repo),candidate_commit:commit(a.candidate_commit),payee:address(a.payee),execution_mode:null,state:states.has(a.state)?a.state:'unknown',reported_state:states.has(a.state)?a.state:'unknown',created_at:number(a.created_at),verification:{accepted:bool(v.accepted),level:null,apple_verified:bool(checks.apple),functional_pass:bool(checks.functional),report_sha256:hash(v.report_sha256)},upload:{file_count:artifacts.length||null,bytes:null,complete:null},inputs:{file_count:null,bytes:null,complete:null},artifacts,source_url:null,error_code:key?null:'task_mapping_unavailable'};if(/^\d+$/.test(String(m?.assignment_id)))out.assignment_id=String(m.assignment_id);attempts.push(out);if(out.created_at!==null)s.latest_record_created_at=Math.max(s.latest_record_created_at??0,out.created_at);if(!key){s.status='partial';s.error_code='task_mapping_unavailable';}}
 s.attempt_count=attempts.length;s.task_count=tasks.length;if(s.invalid_record_count){s.status='partial';s.error_code='invalid_records';}return {attempts,sources:[s],task_metadata};
}
export function readLegacySource(c,{now=Math.floor(Date.now()/1000)}={}){let db;try{db=new DatabaseSync(c.db_path,{readOnly:true});db.exec('PRAGMA query_only=ON; BEGIN');const tasks=db.prepare('SELECT body FROM tasks ORDER BY id').all().map(r=>JSON.parse(r.body));const rows=db.prepare('SELECT body FROM attempts ORDER BY id').all().map(r=>JSON.parse(r.body));const out=projectLegacyRows(tasks,rows,c,{now});db.exec('ROLLBACK');return out;}catch{return errorFeed(c,'bounty-demo','source_unavailable_or_invalid',now);}finally{db?.close();}}
export function mergeFeeds(feeds){return {attempts:feeds.flatMap(f=>f.attempts),sources:feeds.flatMap(f=>f.sources),task_metadata:feeds.flatMap(f=>f.task_metadata??[])};}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{const c=JSON.parse(readFileSync(process.argv[2],'utf8'));const result=mergeFeeds(c.sources.map(s=>s.kind==='bounty-demo'?readLegacySource(s):readArcadeSource(s)));process.stdout.write(JSON.stringify(result)+'\n');}catch{process.stderr.write('Projection configuration refused\n');process.exitCode=2;}}
