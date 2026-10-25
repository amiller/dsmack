import {list,wei,findContract,matches,networkLabel,asset,paymentTx,actualPayment,observationTime} from './view.mjs';
const time=v=>{if(v===null||v===undefined||v==='')return null;const n=typeof v==='number'||/^\d+$/.test(String(v))?Number(v):Date.parse(v);return Number.isFinite(n)&&n>0?(n<1e12?n*1000:n):null;};
const deadline=a=>time(a.deadlines?.[a.state==='reserved'?'submit_by':'review_by']);
const open=t=>t.state==='open';
const funded=t=>{const reward=wei(t.reward_wei),available=wei(t.available_wei),reserved=wei(t.reserved_wei);return open(t)&&reward!==null&&reward>0n&&available!==null&&reserved!==null&&available+reserved>=reward;};
function totals(rows,contracts,field){
 const groups=new Map();for(const row of rows){const c=findContract(row,contracts),amount=wei(row[field]);if(!c||amount===null)continue;const key=String(c.chain_id)+':'+asset(c);if(!groups.has(key))groups.set(key,{key,label:networkLabel(c)+' / '+asset(c),network:networkLabel(c),unit:asset(c),wei:0n,testnet:c.testnet});groups.get(key).wei+=amount;}
 return [...groups.values()].map(g=>({...g,wei:String(g.wei)}));
}
export function market(snapshot,{now=Date.now(),network='',contract=''}={}){
 const contracts=list(snapshot.contracts),match=r=>matches(r,contracts,network,contract),tasks=list(snapshot.tasks).filter(match),assignments=list(snapshot.assignments).filter(match),attempts=list(snapshot.attempts).filter(match),payments=list(snapshot.payments).filter(match);
 const observed=time(observationTime(snapshot)),fresh=observed!==null&&Math.abs(now-observed)<=300000;
 const taskComplete=fresh&&snapshot.coverage?.tasks_complete===true&&Array.isArray(snapshot.tasks)&&tasks.every(t=>['open','closed'].includes(t.state)&&(!open(t)||(wei(t.reward_wei)!==null&&wei(t.available_wei)!==null&&/^\d+$/.test(String(t.active_assignment_id)))));
 const workComplete=taskComplete&&snapshot.coverage?.attempts_complete===true&&Array.isArray(snapshot.assignments)&&Array.isArray(snapshot.attempts);
 const assigned=new Set(assignments.filter(a=>['reserved','submitted'].includes(a.state)).map(a=>a.task_key));
 const available=tasks.filter(t=>!assigned.has(t.key)&&open(t)&&wei(t.reward_wei)>0n&&wei(t.available_wei)!==null&&wei(t.available_wei)>=wei(t.reward_wei)&&/^0+$/.test(String(t.active_assignment_id)));
 const offers=available.map(t=>({...t,slots:String(wei(t.available_wei)/wei(t.reward_wei)),claimable_wei:String((wei(t.available_wei)/wei(t.reward_wei))*wei(t.reward_wei))}));
 const byTask=new Map(tasks.map(t=>[t.key,t]));
 const busy=new Set(),pending=new Set(),expired=[];let uncertainWork=0;
 for(const a of assignments){if(!['reserved','submitted'].includes(a.state))continue;const end=deadline(a);if(end!==null&&end<=now){expired.push(a);continue;}if(end!==null&&funded(byTask.get(a.task_key)??{}))busy.add(a.task_key);else if(end===null)uncertainWork++;}
 for(const a of attempts){const task=byTask.get(a.task_key);if(a.historical||!task||!funded(task)||a.error_code||a.needs_attention||a.deadline?.expired===true)continue;
  const end=time(a.deadline?.expires_at??a.expires_at);if(end!==null&&end<=now)continue;
  if(['queued','preparing'].includes(a.state)&&['self','best_effort'].includes(a.execution_mode)){pending.add(a.task_key);continue;}
  if(['prepared','running','verifying'].includes(a.state)){if(end!==null)busy.add(a.task_key);else uncertainWork++;}
 }
 for(const key of busy)pending.delete(key);
 const windows={};for(const [name,duration]of [['day',86400000],['week',604800000]]){
  const eligible=[],seen=new Set();let unknown=0;
  for(const p of payments){const at=time(p.timestamp??p.created_at);if(at!==null&&at<now-duration)continue;
   if(['funding','deposit','gas'].includes(p.kind)||p.reward_eligible===false)continue;
   if(p.source_withdrawal_transaction_hash!=null||at!==null&&at>now){unknown++;continue;}
   if(p.economic_kind!=='reward'||p.reward_eligible!==true){unknown++;continue;}
   const c=findContract(p,contracts);if(!at||!c||typeof c.testnet!=='boolean'||wei(p.amount_wei)===null||!actualPayment(p)){unknown++;continue;}
   const key=String(c.chain_id)+':'+paymentTx(p).toLowerCase();if(seen.has(key))continue;seen.add(key);eligible.push(p);
  }
  const grouped=totals(eligible,contracts,'amount_wei');windows[name]={testnet:grouped.filter(g=>g.testnet===true),real:grouped.filter(g=>g.testnet===false),complete:fresh&&snapshot.coverage?.reward_accounting_complete===true&&unknown===0,unclassified:unknown};
 }
 return {fresh,observed_at:observationTime(snapshot),available:offers,available_count:{observed:offers.length,complete:taskComplete},slots:offers.reduce((s,t)=>s+BigInt(t.slots),0n).toString(),rewards_available:totals(offers,contracts,'claimable_wei'),in_progress:{observed:busy.size,complete:workComplete&&uncertainWork===0},pending:{observed:pending.size,complete:workComplete&&uncertainWork===0},expired_reservations:expired.length,windows};
}
