'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {pathToFileURL}=require('node:url');
const MAX=8*1024*1024;
const FIELDS={
 contracts:'id name chain_id network testnet address explorer_url asset_symbol block_number block_hash observed_at status coverage error runtime_sha256 deployment_block deployment_tx',
 tasks:'key id contract_id chain_id title issue_url package_hash policy_hash requester reward_wei available_wei reserved_wei deposited_wei effort_wei roles windows state created_tx created_at active_assignment_id submit_window review_window challenge_window',
 assignments:'key id task_key contract_id chain_id worker state candidate_hash evidence_hash delivery_hash payout_wei reserved_wei submitted_at resolved_at created_at deadlines tx transactions txlinks outcome',
 payments:'id kind tx transaction_hash contract_id task_key chain_id recipient amount_wei block_number block_hash timestamp created_at observed_at explorer_url attribution assignment_key',
 activity:'id timestamp kind task_key attempt_id contract_id tx transaction_hash message event fields block_number block_hash log_index explorer_url',
 attempts:'id source_id task_key repository candidate_commit payee execution_mode state created_at updated_at verification upload artifacts source_url error_code needs_attention assignment_id reported_state expires_at task_title task_slug historical inputs deadline',
 credits:'contract_id chain_id account withdrawable_wei block_number block_hash',
 sources:'id name kind status count counts observed_at updated_at scope coverage block_number block_hash error error_code complete from_block to_block indexed_to attempt_count task_count invalid_record_count latest_record_created_at'
};
const FORBIDDEN=/^(capability|cap_hash|execution_cap_hash|node_capability|wallet_authorization|authorization|private_key|secret|access_token|refresh_token|token|password|db_path|stdout|stderr|raw)$/i;
function checkPublic(value,depth=0){
 if(depth>12)throw Error('snapshot nesting limit');
 if(typeof value==='string'&&value.length>20000)throw Error('snapshot string limit');
 if(value&&typeof value==='object')for(const[k,v]of Object.entries(value)){if(FORBIDDEN.test(k))throw Error('private field refused');checkPublic(v,depth+1);}
}
function publicURL(value){
 if(typeof value!=='string')return null;
 try{const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.search)return null;return u.href;}catch{return null;}
}
function project(row,kind){
 const out={};for(const k of FIELDS[kind].split(' '))if(row[k]!==undefined)out[k]=row[k];
 for(const k of ['url','issue_url','explorer_url','source_url'])if(k in out)out[k]=publicURL(out[k]);
 if(kind==='attempts'){
  out.verification=pick(row.verification,'accepted level apple_verified functional_pass report_sha256');
  out.upload=pick(row.upload,'file_count bytes complete');out.inputs=pick(row.inputs,'file_count bytes complete');out.deadline=pick(row.deadline,'expires_at expired');
  out.artifacts=(Array.isArray(row.artifacts)?row.artifacts:[]).map(x=>{const a=pick(x,'name bytes sha256 visibility category');if(x.visibility==='public')a.url=publicURL(x.url);return a;});
 }
 if(kind==='tasks'){out.roles=pick(row.roles,'allocator execution_verifier reviewer delivery_verifier adjudicator');out.windows=pick(row.windows,'submit_seconds review_seconds adjudication_seconds');}
 return out;
}
function pick(o,fields){const r={};if(o&&typeof o==='object')for(const k of fields.split(' '))if(o[k]!==undefined)r[k]=o[k];return r;}
function validateSnapshot(v){
 if(!v||v.schema!=='dsmack-bounty-dashboard-snapshot/1'||!v.chain||!Array.isArray(v.feeds??[]))throw Error('snapshot schema');
 if(typeof v.observed_at!=='string'||!Number.isFinite(Date.parse(v.observed_at))||Date.parse(v.observed_at)>Date.now()+300000)throw Error('snapshot timestamp');
 for(const k of ['contracts','tasks','assignments','payments','activity','sources'])if(!Array.isArray(v.chain[k]))throw Error('chain arrays required');
 if(!v.chain.sources.length||v.chain.sources.some(x=>!x.id||!x.kind||!x.status))throw Error('explicit chain coverage required');
 checkPublic(v);const out={schema:v.schema,observed_at:v.observed_at,chain:{},feeds:[]};
 for(const k of ['contracts','tasks','assignments','payments','activity','sources','credits']){const a=v.chain[k]??[];if(!Array.isArray(a)||a.length>50000)throw Error('snapshot array bound');out.chain[k]=a.map(x=>project(x,k));}
 for(const f of v.feeds??[]){if(!Array.isArray(f.attempts)||!Array.isArray(f.sources)||f.attempts.length>20000)throw Error('feed bound');out.feeds.push({attempts:f.attempts.map(x=>project(x,'attempts')),sources:f.sources.map(x=>project(x,'sources')),task_metadata:(f.task_metadata??[]).map(x=>pick(x,'task_key title issue_url repository source_id'))});}
 return out;
}
async function body(req){let size=0,parts=[];for await(const b of req){size+=b.length;if(size>MAX)throw Error('body limit');parts.push(b);}return JSON.parse(Buffer.concat(parts).toString('utf8'));}
function json(res,status,value){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(value));}
function createHandler(config){
 const root=path.resolve(config.data_dir),snapshot=path.join(root,'snapshot.json'),web=path.resolve(config.web_dir??path.join(__dirname,'web'));
 fs.mkdirSync(root,{recursive:true,mode:0o700});let projection;
 async function feeds(){
  if(!config.stores?.length)return [];
  try{projection??=import(pathToFileURL(path.join(__dirname,'feeds/project.mjs')).href);const m=await projection;return await Promise.all(config.stores.map(c=>m.readArcadeSource(c,{now:Math.floor(Date.now()/1000)})));}
  catch{return config.stores.map(c=>({attempts:[],sources:[{id:c.id,kind:'attempt-store',status:'unavailable',error_code:'attempt_source_unavailable'}]}));}
 }
 async function data(){
  let s,stale=false;
  try{s=validateSnapshot(JSON.parse(fs.readFileSync(snapshot,'utf8')));stale=Date.now()-Date.parse(s.observed_at)>5*60*1000;}
  catch{s={chain:{contracts:[],tasks:[],assignments:[],payments:[],activity:[],sources:[{id:'chain-index',kind:'chain',status:'unavailable',error_code:'no_valid_snapshot'}]},feeds:[]};}
  const live=await feeds(),all=[...s.feeds,...live],attempts=all.flatMap(f=>f.attempts??[]).map(a=>project(a,'attempts'));
  const unique=[...new Map(attempts.map(a=>[(a.source_id??'')+':'+a.id,a])).values()];
  const metadata=all.flatMap(f=>f.task_metadata??[]);for(const t of s.chain.tasks??[]){const m=metadata.filter(x=>x.task_key===t.key);for(const k of ['title','issue_url','repository']){const vals=[...new Set(m.map(x=>x[k]).filter(x=>typeof x==='string'&&x.length<=500))];if(vals.length===1)t[k]=k==='issue_url'?publicURL(vals[0]):vals[0];}}
  const sources=[...(s.chain.sources??[]),...all.flatMap(f=>f.sources??[])].map(x=>project(x,'sources'));
  for(const x of sources)if(x.kind==='chain'&&(stale||!x.observed_at||Date.now()-Date.parse(x.observed_at)>5*60*1000)&&['ok','indexing','observed'].includes(x.status))x.status='stale';
  for(const c of s.chain.contracts??[])if(!c.observed_at||Date.now()-Date.parse(c.observed_at)>5*60*1000)c.status=c.status==='unknown'?'unknown':'stale';
  const attemptSources=sources.filter(x=>x.kind!=='chain');for(const id of config.expected_feed_ids??[])if(!attemptSources.some(x=>x.id===id)){const x={id,kind:'attempt-store',status:'unavailable',error_code:'no_feed_snapshot'};sources.push(x);attemptSources.push(x);}
  const anyAttempts=attemptSources.some(x=>['ok','partial'].includes(x.status));const coverage={tasks_complete:(s.chain.contracts??[]).length>0&&(s.chain.contracts??[]).every(x=>['observed','stale'].includes(x.status)&&x.coverage?.getters==='all IDs at pinned block'),attempts_complete:attemptSources.length>0&&attemptSources.every(x=>x.status==='ok'),payments_complete:(s.chain.contracts??[]).length>0&&(s.chain.contracts??[]).every(x=>['observed','stale'].includes(x.status)&&x.coverage?.events_complete===true)};
  return {schema:'dsmack-bounty-dashboard/1',built_at:new Date().toISOString(),snapshot_observed_at:s.observed_at??null,...s.chain,credits:(s.chain.contracts??[]).length>0&&(s.chain.contracts??[]).every(x=>['observed','stale'].includes(x.status)&&x.coverage?.credit_balances==='all observed recipients at pinned block')?s.chain.credits:null,tasks:(s.chain.contracts??[]).some(x=>['observed','stale'].includes(x.status))?s.chain.tasks:null,assignments:(s.chain.contracts??[]).some(x=>['observed','stale'].includes(x.status))?s.chain.assignments:null,attempts:anyAttempts?unique:null,sources,coverage};
 }
 async function handler(req,res){
  if(!req&&!res)return;
  if(req?.url==='/_warmup'){res.end('');return;}
  try{
   const u=new URL(req.url,'http://local');if(u.search) return json(res,400,{error:'query parameters refused'});
   const base=config.base_path??'/bounties';let p=u.pathname;
   if(p===base||p.startsWith(base+'/'))p=p.slice(base.length)||'/';
   res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");res.setHeader('Referrer-Policy','no-referrer');
   if(req.method==='GET'&&p==='/api/dashboard')return json(res,200,await data());
   if(req.method==='GET'&&p==='/api/health'){
    const {DatabaseSync}=require('node:sqlite'),rows=[];
    for(const c of config.stores??[]){let db;try{db=new DatabaseSync(c.db_path,{readOnly:true});const counts=db.prepare('SELECT kind,count(*) AS count FROM records GROUP BY kind').all().filter(r=>['attempt','config'].includes(r.kind));rows.push({id:c.id,status:'ok',counts});}catch{rows.push({id:c.id,status:'unavailable'});}finally{db?.close();}}
    return json(res,200,{stores:rows});
   }
   if(req.method==='PUT'&&p==='/api/snapshot'){
    const t=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization??'')?.[1];const digest=crypto.createHash('sha256').update(t??'').digest('hex');
    if(!config.ingest_token_sha256||!t||!crypto.timingSafeEqual(Buffer.from(digest),Buffer.from(config.ingest_token_sha256)))return json(res,401,{error:'unauthorized'});
    let v;try{v=validateSnapshot(await body(req));}catch{return json(res,400,{error:'invalid public snapshot'});}const tmp=path.join(root,'snapshot-'+crypto.randomBytes(12).toString('hex')+'.tmp');
    try{fs.writeFileSync(tmp,JSON.stringify(v),{mode:0o600,flag:'wx'});fs.renameSync(tmp,snapshot);}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}
    return json(res,200,{accepted:true,observed_at:v.observed_at});
   }
   const allowed=['index.html','app.mjs','style.css','view.mjs'];const name=p==='/'?'index.html':p.slice(1);
   if(req.method==='GET'&&allowed.includes(name)){
    const b=fs.readFileSync(path.join(web,name));res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.mjs')?'text/javascript':'text/css','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});return res.end(b);
   }
   return json(res,405,{error:'read-only dashboard'});
  }catch{return json(res,503,{error:'dashboard source unavailable'});}
 }
 return handler;
}
module.exports={createHandler,validateSnapshot,project,publicURL};
