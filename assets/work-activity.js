const DASHBOARD='https://pod.dstack.soc1024.com/bounties/';
const FEED=DASHBOARD+'api/dashboard';
const DIRECTORY='https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft/directory';
const host=document.getElementById('work-activity');
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const date=value=>{const d=new Date(typeof value==='number'?value*1000:value);return value!=null&&Number.isFinite(d.getTime())?d:null;};
const stamp=value=>date(value)?.toLocaleString()||'Unknown';
const safeURL=value=>{try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password?u.href:null;}catch{return null;}};
function link(text,url){const a=el('a',text);a.href=safeURL(url)||DASHBOARD;return a;}
async function get(url){const r=await fetch(url,{method:'GET',credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('Unavailable');return r.json();}
function count(rows,complete){return !Array.isArray(rows)?'Unknown':complete?String(rows.length):rows.length?'≥'+rows.length:'Unknown';}
function metric(label,value){const n=el('div',undefined,'work-stat');n.append(el('strong',value),el('span',label));return n;}
function money(wei){const whole=wei/1000000000000000000n;const fraction=(wei%1000000000000000000n).toString().padStart(18,'0').replace(/0+$/,'');return whole+(fraction?'.'+fraction:'');}
function renderWork(data){
 const box=el('div');const observed=date(data.snapshot_observed_at);const stale=!observed||Date.now()-observed.getTime()>300000;
 const coverage=data.coverage||{};const attempts=Array.isArray(data.attempts)?data.attempts:null;
 const full=attempts?.filter(a=>a.verification?.accepted===true&&a.verification?.level==='full'&&a.verification?.apple_verified===true&&a.verification?.functional_pass===true);
 const payments=Array.isArray(data.payments)?data.payments:null;
 const withdrawals=payments?.filter(p=>p.kind==='withdrawal'&&p.chain_id===84532&&/^0x[0-9a-f]{64}$/i.test(p.transaction_hash||'')&&/^\d+$/.test(p.amount_wei||''));
 let total='Unknown';if(withdrawals&&(withdrawals.length||coverage.payments_complete)){total=money(withdrawals.reduce((s,p)=>s+BigInt(p.amount_wei),0n))+(coverage.payments_complete?'':' + unknown');}
 const metrics=el('div',undefined,'work-stats');metrics.append(metric('Tasks',count(data.tasks,coverage.tasks_complete)),metric('Recorded attempts',count(attempts,coverage.attempts_complete)),metric('FULL-verified attempts',count(full,coverage.attempts_complete)),metric('Base Sepolia test ETH withdrawn',total));box.append(metrics);
 const partial=!coverage.tasks_complete||!coverage.attempts_complete||!coverage.payments_complete;
 box.append(el('p',`Snapshot: ${stamp(data.snapshot_observed_at)}${stale?' · Stale observation':''}${partial?' · Partial coverage':''}`, 'work-meta'));
 const titles=new Map((data.tasks||[]).map(t=>[t.key,t.title||'Task '+t.id]));
 const recent=[...(withdrawals||[]).map(p=>({at:p.created_at||p.timestamp,title:'Testnet reward withdrawn',detail:money(BigInt(p.amount_wei))+' test ETH · Base Sepolia',url:p.explorer_url})),...(attempts||[]).map(a=>({at:a.created_at,title:titles.get(a.task_key)||a.repository||'Task attempt',detail:(a.historical?'Recorded ':'')+(a.state||'Unknown')+' · '+(a.source_id||'Attempt record'),url:a.source_url}))].sort((a,b)=>(date(b.at)?.getTime()||0)-(date(a.at)?.getTime()||0)).slice(0,3);
 const list=el('ul',undefined,'work-recent');for(const item of recent){const li=el('li');li.append(link(item.title,item.url),el('span',item.detail),el('time',stamp(item.at)));list.append(li);}if(recent.length)box.append(list);
 box.append(link('View tasks, attempts and payments →',DASHBOARD));return box;
}
function renderDirectory(data){
 const box=el('p',undefined,'work-directory');const generated=date(data.generatedAt);const now=Date.now();
 if(data.type!=='dsmack-native-directory'||data.status!=='available'||!generated||now-generated.getTime()>300000||!Array.isArray(data.nodes)){box.append(el('span','Earlier shared-key network: check-ins unavailable. '),link('Open its directory →',new URL('nodes/',location.href).href));return box;}
 const fresh=data.nodes.filter(n=>n.checkIn?.status==='fresh'&&date(n.checkIn.expiresAt)?.getTime()>now);
 const latest=fresh.map(n=>date(n.checkIn.lastVerifiedAt)?.getTime()||0).sort((a,b)=>b-a)[0];
 box.append(el('span',`Earlier shared-key network: ${fresh.length} recent relay check-in${fresh.length===1?'':'s'}.${latest?' Last check-in: '+new Date(latest).toLocaleString()+'.':''} `),link('Directory →',new URL('nodes/',location.href).href));return box;
}
let busy=false;
async function refresh(){if(!host||busy||document.hidden)return;busy=true;const [work,directory]=await Promise.allSettled([get(FEED),get(DIRECTORY)]);const fragment=document.createDocumentFragment();try{fragment.append(work.status==='fulfilled'?renderWork(work.value):el('p','Work and payment observations are unavailable. Open the dashboard for source status.'));}catch{fragment.append(el('p','Work and payment observations are unavailable.'));}try{fragment.append(directory.status==='fulfilled'?renderDirectory(directory.value):el('p','Earlier shared-key network: check-ins unavailable.','work-directory'));}catch{fragment.append(el('p','Earlier shared-key network: check-ins unavailable.','work-directory'));}host.replaceChildren(fragment);busy=false;}
refresh();setInterval(refresh,60000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
