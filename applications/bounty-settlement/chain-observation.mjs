// Read-only Base Sepolia projection for the exact reviewed WorkEscrow runtime.
// RPC is an operator trust boundary; this module does not prove Ethereum state.
import { exact, need, sha } from '../bounty-demo/core.mjs';
export const RUNTIME_SHA256='dd3596a61b94402a0161b950319d726fed7ffd0fd384774fa562d07b06aa6daa';
const CALL={task:'17751a21',assignment:'c806bb2c',withdrawable:'ce513b6f'};
const EVENT={funding:'07ac3fb1085d6fdbf9a1527cea6bf23ff6fb16825736c0ad6cbc87ce5e5f6b7e',assignment:'c3e68b06d87a16c5f46c453173e52bc33b8250efd5d62e742702f1e258fee280',resolution:'9e8270be22c213149f278b5bf643fc5f79654f93c3751cae4912cf8c445552ac',close:'e31eb033942fcbd12ae4a23e2ec0917b2818a7b539c55f083e897e21e0ce219b',withdrawal:'7084f5476618d8e60b11ef0d7d3f06914655adb8793e28ff7f018d4c76d505d5'};
const ROLE=['allocator','executionVerifier','reviewer','deliveryVerifier','adjudicator'];
const NUM=['effortPay','completionPay','submitSeconds','reviewSeconds','adjudicationSeconds'];
const decimal=x=>typeof x==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(x)&&BigInt(x)<2n**256n;
const hex=(x,n)=>typeof x==='string'&&new RegExp('^0x[a-fA-F0-9]{'+n+'}$').test(x);
const address=x=>hex(x,40)&&x!=='0x'+'0'.repeat(40);
const same=(a,b)=>need(a===b,'chain observation selection mismatch');
function quantity(x){need(typeof x==='string'&&/^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(x),'invalid RPC quantity');return BigInt(x);}
function words(x,n){need(hex(x,n*64),'invalid static ABI result');return Array.from({length:n},(_,i)=>x.slice(2+i*64,2+(i+1)*64).toLowerCase());}
const uint=w=>BigInt('0x'+w).toString();
function addr(w){need(w.slice(0,24)==='0'.repeat(24),'noncanonical ABI address');return '0x'+w.slice(24);}
const word=n=>BigInt(n).toString(16).padStart(64,'0');
function validate(s){
 exact(s,['chain_id','escrow','runtime_sha256','task_id','assignment_id','requester','worker','account','terms','expected_commitments','minimum_confirmations','transactions']);
 same(s.chain_id,84532);same(s.runtime_sha256,RUNTIME_SHA256);
 for(const k of ['escrow','requester','worker','account'])need(address(s[k])&&s[k]===s[k].toLowerCase(),'normalized selected address required');
 need([s.requester,s.worker].includes(s.account),'selected account must be requester or worker');
 need(decimal(s.task_id)&&BigInt(s.task_id)>0n,'selected task ID required');need(s.assignment_id===null||(decimal(s.assignment_id)&&BigInt(s.assignment_id)>0n),'invalid assignment ID');
 if(s.expected_commitments!==null){exact(s.expected_commitments,['candidate','evidence','delivery']);for(const v of Object.values(s.expected_commitments))need(hex(v,64)&&v===v.toLowerCase()&&v!=='0x'+'0'.repeat(64),'selected submission commitment required');}
 exact(s.terms,['packageHash','policyHash',...ROLE,...NUM]);
 for(const k of ['packageHash','policyHash'])need(hex(s.terms[k],64)&&s.terms[k]===s.terms[k].toLowerCase(),'selected terms digest required');
 for(const k of ROLE)need(address(s.terms[k])&&s.terms[k]===s.terms[k].toLowerCase(),'selected oracle address required');
 for(const k of NUM)need(decimal(s.terms[k]),'selected integer terms required');
 need(Number.isSafeInteger(s.minimum_confirmations)&&s.minimum_confirmations>=1&&s.minimum_confirmations<=128,'explicit confirmation depth required');
 need(Array.isArray(s.transactions)&&s.transactions.length<=16,'bounded receipt selections required');const seen=new Set();
 for(const t of s.transactions){exact(t,['kind','hash']);need(Object.hasOwn(EVENT,t.kind)&&hex(t.hash,64)&&!seen.has(t.hash.toLowerCase()),'unique selected receipt required');seen.add(t.hash.toLowerCase());}
 return JSON.parse(JSON.stringify(s));
}
export function readOnlyRpc(url='https://sepolia.base.org'){
 need(new URL(url).protocol==='https:','HTTPS RPC required');
 const allowed=new Set(['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getCode','eth_call','eth_getTransactionReceipt']);
 return async(method,params)=>{
  need(allowed.has(method),'read-only RPC method required');
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(10000),redirect:'error'});
  need(response.ok&&response.body,'chain RPC unavailable');
  const parts=[];let size=0;
  for await(const part of response.body){size+=part.length;if(size>1048576){throw new Error('bounded RPC response required');}parts.push(part);}
  const text=Buffer.concat(parts).toString('utf8');
  const value=JSON.parse(text);need(value.id===1&&!value.error&&Object.hasOwn(value,'result'),'chain RPC refused');return value.result;
 };
}
export async function observeChain(selection,rpc,{now=()=>Math.floor(Date.now()/1000)}={}){
 const s=validate(selection);same(quantity(await rpc('eth_chainId',[])),84532n);
 const tip=quantity(await rpc('eth_blockNumber',[]));need(tip>=BigInt(s.minimum_confirmations-1),'chain too young');
 const height=tip-BigInt(s.minimum_confirmations-1),block='0x'+height.toString(16),header=await rpc('eth_getBlockByNumber',[block,false]);
 need(header&&hex(header.hash,64)&&quantity(header.number)===height,'selected block unavailable');
 const code=await rpc('eth_getCode',[s.escrow,block]);need(typeof code==='string'&&/^0x([a-fA-F0-9]{2})+$/.test(code),'escrow code unavailable');same(sha(Buffer.from(code.slice(2),'hex')),s.runtime_sha256);
 const call=async(selector,arg,n)=>words(await rpc('eth_call',[{to:s.escrow,data:'0x'+selector+arg},block]),n);
 const t=await call(CALL.task,word(s.task_id),16);same(addr(t[0]),s.requester);need(['0','1'].includes(uint(t[1])),'noncanonical task flag');
 same('0x'+t[4],s.terms.packageHash);same('0x'+t[5],s.terms.policyHash);
 ROLE.forEach((k,i)=>same(addr(t[6+i]),s.terms[k]));NUM.forEach((k,i)=>same(uint(t[11+i]),s.terms[k]));
 let a=null;
 if(s.assignment_id!==null){
  a=await call(CALL.assignment,word(s.assignment_id),9);same(uint(a[0]),s.task_id);same(addr(a[1]),s.worker);need(BigInt(uint(a[2]))<=5n,'invalid assignment state');
  need(uint(t[3])==='0'||uint(t[3])===s.assignment_id,'task has another active assignment');
  if(['2','3','4'].includes(uint(a[2])))need(s.expected_commitments!==null,'submission identity must be independently selected');
  if(s.expected_commitments!==null)['candidate','evidence','delivery'].forEach((k,i)=>same('0x'+a[6+i],s.expected_commitments[k]));
 }
 const credit=uint((await call(CALL.withdrawable,s.account.slice(2).padStart(64,'0'),1))[0]);
 const events=[];
 for(const chosen of s.transactions){
  const r=await rpc('eth_getTransactionReceipt',[chosen.hash]);need(r&&r.status==='0x1'&&hex(r.blockHash,64)&&hex(r.transactionHash,64),'successful included receipt required');same(r.transactionHash.toLowerCase(),chosen.hash.toLowerCase());
  const rh=quantity(r.blockNumber);need(rh<=height,'receipt not confirmed to selected depth');
  const canonical=await rpc('eth_getBlockByNumber',[r.blockNumber,false]);need(canonical&&hex(canonical.hash,64),'receipt block unavailable');same(canonical.hash.toLowerCase(),r.blockHash.toLowerCase());
  need(Array.isArray(r.logs)&&r.logs.length<=128,'bounded receipt logs required');
  const matches=r.logs.filter(l=>typeof l.address==='string'&&l.address.toLowerCase()===s.escrow&&Array.isArray(l.topics)&&l.topics[0]?.toLowerCase()==='0x'+EVENT[chosen.kind]);
  const selected=matches.filter(l=>{
   if(chosen.kind==='withdrawal')return l.topics[1]?.toLowerCase()==='0x'+s.account.slice(2).padStart(64,'0');
   const id=['assignment','resolution'].includes(chosen.kind)?s.assignment_id:s.task_id;
   return id!==null&&l.topics[1]?.toLowerCase()==='0x'+word(id);
  });
  need(selected.length===1,'exact selected escrow event required');const l=selected[0];need(l.removed!==true&&l.blockHash?.toLowerCase()===r.blockHash.toLowerCase()&&l.transactionHash?.toLowerCase()===r.transactionHash.toLowerCase(),'event receipt identity mismatch');
  const topics=l.topics.map(x=>words(x,1)[0]);quantity(l.logIndex);let amount;
  if(chosen.kind==='funding'){need(topics.length===3,'funding topic count');same(addr(topics[2]),s.requester);const d=words(l.data,3);same('0x'+d[0],s.terms.packageHash);same('0x'+d[1],s.terms.policyHash);amount=uint(d[2]);}
  if(chosen.kind==='assignment'){need(topics.length===4,'assignment topic count');same(uint(topics[2]),s.task_id);same(addr(topics[3]),s.worker);const d=words(l.data,2);same(uint(d[0]),s.terms.completionPay);amount=uint(d[0]);}
  if(chosen.kind==='resolution'){need(topics.length===2,'resolution topic count');const d=words(l.data,2);need(BigInt(uint(d[0]))<=2n,'invalid resolved outcome');amount=uint(d[1]);const outcome=Number(uint(d[0]));need(a&&uint(a[2])===(['4','3','3'][outcome]),'resolution state mismatch');same(amount,outcome===0?'0':s.terms[outcome===1?'effortPay':'completionPay']);}
  if(chosen.kind==='close'){need(topics.length===2&&uint(t[1])==='0','closed task required');amount=uint(words(l.data,1)[0]);}
  if(chosen.kind==='withdrawal'){need(topics.length===2,'withdrawal topic count');amount=uint(words(l.data,1)[0]);}
  events.push({kind:chosen.kind,amount_wei:amount,account:chosen.kind==='withdrawal'?s.account:null,transaction_hash:chosen.hash.toLowerCase(),block_hash:r.blockHash.toLowerCase(),block_number:rh.toString(),log_index:quantity(l.logIndex).toString(),receipt_url:'https://sepolia.basescan.org/tx/'+chosen.hash.toLowerCase()});
 }
 const finalHeader=await rpc('eth_getBlockByNumber',[block,false]);same(finalHeader?.hash,header.hash);
 return {status:'observed',chain_id:84532,network:'Base Sepolia testnet',authority:'operator-selected RPC; no cryptographic state proof',observed_at:now(),block_number:height.toString(),block_hash:header.hash,confirmation_state:'confirmed-depth-only',minimum_confirmations:s.minimum_confirmations,escrow:s.escrow,task_id:s.task_id,assignment_id:s.assignment_id,funding:{task_open:uint(t[1])==='1',available_wei:uint(t[2]),reserved_wei:a?uint(a[3]):null},credit:{account:s.account,withdrawable_wei:credit,assignment_state:a?['none','reserved','submitted','settled','rejected','expired'][Number(uint(a[2]))]:null},account_withdrawals:events.filter(e=>e.kind==='withdrawal'),events,per_task_received:false};
}
export function createChainObserver(selections,{rpc=readOnlyRpc(),now=()=>Math.floor(Date.now()/1000)}={}){
 need(selections&&Object.getPrototypeOf(selections)===Object.prototype&&Object.keys(selections).length<=32,'bounded selected task map required');
 const selected=Object.fromEntries(Object.entries(selections).map(([id,s])=>{need(/^[a-z0-9-]{1,80}$/.test(id),'local task ID required');return[id,validate(s)];}));
 const cache=new Map(),inflight=new Map();
 return async id=>{
  if(!Object.hasOwn(selected,id))return {status:'not_configured'};
  const old=cache.get(id);if(old&&now()-old.checked_at<15)return old.value;
  if(inflight.has(id))return inflight.get(id);
  const pending=(async()=>{let value;try{value=await observeChain(selected[id],rpc,{now});}catch{value={status:old?.last_success?'stale':'unknown',chain_id:84532,checked_at:now(),last_success:old?.last_success??null,reason:'Chain observation unavailable or inconsistent; no current payment conclusion.'};}
   cache.set(id,{checked_at:now(),value,last_success:value.status==='observed'?value:old?.last_success??null});return value;
  })();inflight.set(id,pending);try{return await pending;}finally{inflight.delete(id);}
 };
}
