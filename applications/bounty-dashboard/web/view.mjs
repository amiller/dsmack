export const list=v=>Array.isArray(v)?v:[];
export const text=(v,fallback='Unknown')=>v===null||v===undefined||v===''?fallback:String(v);
export function wei(v){if(typeof v==='bigint')return v>=0n?v:null;if(typeof v==='number')return Number.isSafeInteger(v)&&v>=0?BigInt(v):null;if(typeof v!=='string'||!/^\d+$/.test(v)||v.length>90)return null;return BigInt(v);}
export function decimal(v,decimals=18){const n=wei(v);if(n===null)return 'Unknown';const scale=10n**BigInt(decimals),whole=n/scale,part=(n%scale).toString().padStart(decimals,'0').replace(/0+$/,'');return whole.toString()+(part?'.'+part:'');}
export function short(v){const s=text(v);return s.length>22?s.slice(0,10)+'…'+s.slice(-7):s;}
export function safeURL(v){if(typeof v!=='string'||v.length>4096)return null;if(v.startsWith('/')&&!v.startsWith('//')&&!v.includes('\\'))return v;try{const u=new URL(v);return u.protocol==='https:'&&!u.username&&!u.password?u.href:null;}catch{return null;}}
export function time(v){if(v===null||v===undefined||v===''||v===0||v==='0')return 'Unknown';let n=v;if(typeof n==='string'&&/^\d+$/.test(n))n=Number(n);if(typeof n==='number')n=n<1e12?n*1000:n;const d=new Date(n);return Number.isNaN(d.getTime())?'Unknown':d.toLocaleString();}
export const contractId=c=>text(c?.id,'');
export const networkKey=c=>text(c?.chain_id??contractId(c).split(':')[0],'unknown');
export function asset(c){const chain=networkKey(c),symbol=c?.asset_symbol??(['1','8453','84532','11155111'].includes(chain)?'ETH':'native units');return (c?.testnet===true?'test ':'')+symbol;}
export const networkLabel=c=>text(c?.network??c?.name,networkKey(c))+(c?.testnet===true?' · testnet':'');
export function findContract(row,contracts){return list(contracts).find(c=>contractId(c)===row?.contract_id||String(row?.task_key??row?.key??'').startsWith(contractId(c)+':'));}
export function matches(row,contracts,network,contract){if(!network&&!contract)return true;const c=findContract(row,contracts);return !!c&&(!network||networkKey(c)===network)&&(!contract||contractId(c)===contract);}
export function paymentTx(p){return p?.tx??p?.transaction_hash??p?.actual_tx;}
export function actualPayment(p){return (['withdrawal','withdrawn','refund','refunded'].includes(p?.kind??p?.type)||(p?.kind==='direct_reward'&&p.receipt_verified===true))&&/^0x[0-9a-fA-F]{64}$/.test(paymentTx(p)??'');}
export function attemptStatus(a){if(a.historical===true&&['running','claimed','registered','queued','prepared','preparing','uploading','verifying','leased','pending','created'].includes(String(a.state).toLowerCase()))return 'Recorded '+text(a.state).replaceAll('_',' ');if(a.needs_attention||a.error_code||/^claim_(uncertain|failed)$/.test(a.state??''))return 'Needs attention';if(a.verification?.accepted===true&&a.verification.level==='full'&&a.verification.functional_pass===true)return 'Verified';return text(a.state,'Unknown').replaceAll('_',' ');}
export function assignmentStatus(a,now=Date.now()){const s=String(a.state??'').toLowerCase(),d=a.deadlines??{},deadline=s==='reserved'?(d.submit_by??d.submitBy):s==='submitted'?(d.review_by??d.reviewBy):null;if(deadline!==null){let n=Number(deadline);if(n<1e12)n*=1000;if(Number.isFinite(n)&&n>0&&n<now)return 'Window expired (computed)';}return text(a.state);}
export function groups(rows,contracts,field){const map=new Map();for(const row of rows){const c=findContract(row,contracts),id=(c?networkKey(c):'unknown')+':'+asset(c),label=(c?networkLabel(c):'Unknown network')+' / '+asset(c);if(!map.has(id))map.set(id,{label,total:0n,unknown:0,count:0});const g=map.get(id),n=wei(row[field]);g.count++;if(n===null)g.unknown++;else g.total+=n;}return [...map.values()].map(g=>({label:g.label,value:g.unknown===g.count?'Unknown':decimal(g.total)+(g.unknown?' + unknown':''),unknown:g.unknown}));}

export function coverage(v){if(v===null||v===undefined)return 'Unknown';if(typeof v!=='object')return String(v);return Object.entries(v).map(([k,x])=>k.replaceAll('_',' ')+': '+text(x)).join(' · ');}
export const incompleteEvents=s=>list(s?.contracts).some(c=>c.coverage?.events_complete===false);
export function taskStatus(task,assignments,now=Date.now()){const active=list(assignments).filter(a=>a.task_key===task.key&&((task.active_assignment_id&&String(task.active_assignment_id)===String(a.id))||['reserved','submitted'].includes(String(a.state).toLowerCase())));return active.some(a=>assignmentStatus(a,now)==='Window expired (computed)')?'Window expired (computed)':text(task.state);}
export const observationTime=s=>Object.hasOwn(s??{},'snapshot_observed_at')?s.snapshot_observed_at:s?.built_at;
export function recordCoverage(s,field){
 if(!Array.isArray(s?.[field]))return 'unknown';
 const complete=s.coverage?.[field+'_complete'];if(complete===true)return 'complete';
 if(field==='attempts'){
  const sources=list(s.sources).filter(x=>['arcade-pilot','bounty-demo'].includes(x.kind));
  if(sources.length&&!sources.some(x=>['ok','partial'].includes(x.status)))return 'unknown';
 }
 return 'partial';
}
export const countLabel=(count,state)=>state==='unknown'||(state==='partial'&&count===0)?'Unknown':(state==='partial'?'≥':'')+count;
export function observedGroups(rows,contracts,field,state){return groups(rows,contracts,field).map(g=>({...g,value:state==='unknown'?'Unknown':state!=='complete'&&g.value!=='Unknown'&&!g.value.includes('unknown')?g.value+' + unknown':g.value}));}
export function paymentTaskLabel(p){return p?.task_key?null:['withdrawal','withdrawn'].includes(p?.kind??p?.type)?'Pooled / task unknown':'Task unknown';}
export const artifactCategory=a=>a?.category==='input'?'Inputs':a?.category==='evidence'||a?.category===undefined?'Evidence':'Other artifacts';

export function paymentKind(p){
 const kind=p?.kind??p?.type;
 if(['withdrawal','withdrawn'].includes(kind)){if(p.economic_kind==='reward')return 'Reward withdrawal';if(p.economic_kind==='refund')return 'Refund withdrawal';}
 if(kind==='direct_reward'){if(p.economic_kind==='reward'&&p.reward_eligible===false&&/^0x[0-9a-f]{64}$/i.test(p.source_withdrawal_transaction_hash??''))return 'Reward forwarded';if(p.economic_kind==='unclassified'||p.reward_eligible===null)return 'Direct transfer';return 'Direct reward';}
 return text(kind);
}
export const canaryState=e=>e.burned===true?'Burned':e.burned===false&&wei(e.pot_wei)===0n?'Reclaimed':e.burned===false&&wei(e.pot_wei)>0n?'Armed':'Unknown';
