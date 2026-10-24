import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {observeChain,createChainObserver,RUNTIME_SHA256} from './chain-observation.mjs';
const code=readFileSync(new URL('../arcade-pilot/chain/fixtures/WorkEscrow.runtime.hex',import.meta.url),'utf8').trim();
const addr=n=>'0x'+String(n).repeat(40),digest=n=>'0x'+String(n).repeat(64),w=n=>BigInt(n).toString(16).padStart(64,'0'),aw=a=>a.slice(2).padStart(64,'0'),abi=xs=>'0x'+xs.join('');
const selection={chain_id:84532,escrow:addr(1),runtime_sha256:RUNTIME_SHA256,task_id:'1',assignment_id:'1',requester:addr(2),worker:addr(3),account:addr(3),terms:{packageHash:digest(4),policyHash:digest(5),allocator:addr(2),executionVerifier:addr(6),reviewer:addr(7),deliveryVerifier:addr(8),adjudicator:addr(9),effortPay:'5',completionPay:'10',submitSeconds:'300',reviewSeconds:'60',adjudicationSeconds:'60'},expected_commitments:{candidate:digest('d'),evidence:digest('e'),delivery:digest('f')},minimum_confirmations:2,transactions:[{kind:'resolution',hash:digest('a')},{kind:'withdrawal',hash:digest('b')}]};
function fixture({outcome=2,state=3,payout=10,credit=0,fail=false,reorg=false,wrongPayee=false,wrongPolicy=false,missingEvent=false}={}){
 const calls=[];let blockReads=0;
 const rpc=async(method,args)=>{
  calls.push([method,args]);if(fail)throw Error('offline');
  if(method==='eth_chainId')return '0x14a34';
  if(method==='eth_blockNumber')return '0x65';
  if(method==='eth_getBlockByNumber'){blockReads++;return {number:args[0],hash:reorg&&blockReads>3?digest('e'):digest('c')};}
  if(method==='eth_getCode')return code;
  if(method==='eth_call'){
   const data=args[0].data;
   if(data.startsWith('0x17751a21'))return abi([aw(addr(2)),w(1),w(0),w(0),digest(4).slice(2),(wrongPolicy?digest(6):digest(5)).slice(2),...[2,6,7,8,9].map(n=>aw(addr(n))),...[5,10,300,60,60].map(w)]);
   if(data.startsWith('0xc806bb2c'))return abi([w(1),aw(wrongPayee?addr(4):addr(3)),w(state),w(0),w(300),w(400),...['d','e','f'].map(n=>digest(n).slice(2))]);
   if(data.startsWith('0xce513b6f'))return abi([w(credit)]);
  }
  if(method==='eth_getTransactionReceipt'){
   const withdraw=args[0]===digest('b');
   const log={address:addr(1),topics:withdraw?['0x7084f5476618d8e60b11ef0d7d3f06914655adb8793e28ff7f018d4c76d505d5','0x'+aw(addr(3))]:['0x9e8270be22c213149f278b5bf643fc5f79654f93c3751cae4912cf8c445552ac','0x'+w(1)],data:abi(withdraw?[w(10)]:[w(outcome),w(payout)]),blockHash:digest('c'),transactionHash:args[0],logIndex:'0x0'};
   return {status:'0x1',transactionHash:args[0],blockNumber:'0x64',blockHash:digest('c'),logs:missingEvent?[]:[log]};
  }
  throw Error('unexpected RPC '+method);
 };
 return {rpc,calls};
}
test('confirmed settlement and account withdrawal remain distinct from task receipt',async()=>{
 const f=fixture();const r=await observeChain(selection,f.rpc,{now:()=>500});
 assert.equal(r.credit.assignment_state,'settled');assert.equal(r.account_withdrawals[0].amount_wei,'10');assert.equal(r.per_task_received,false);assert.equal(r.confirmation_state,'confirmed-depth-only');
 assert(f.calls.filter(([m])=>['eth_getCode','eth_call'].includes(m)).every(([,a])=>a.at(-1)==='0x64'));
 assert(!f.calls.some(([m])=>m.includes('send')||m.includes('sign')));
});
test('rejection with nonzero effort fee correctly expects zero payout',async()=>{
 const r=await observeChain({...selection,transactions:[selection.transactions[0]]},fixture({outcome:0,state:4,payout:0}).rpc);assert.equal(r.events[0].amount_wei,'0');
});
for(const [name,options]of Object.entries({payee:{wrongPayee:true},policy:{wrongPolicy:true},outcome:{outcome:0,state:4,payout:5},state:{state:1},missing:{missingEvent:true},reorg:{reorg:true}}))test('refuses '+name+' mismatch',async()=>assert.rejects(observeChain(selection,fixture(options).rpc)));
test('RPC outage makes previous observation stale and first observation unknown',async()=>{
 let time=100,offline=false;const f=fixture();const observer=createChainObserver({demo:selection},{now:()=>time,rpc:(...args)=>offline?Promise.reject(Error('offline')):f.rpc(...args)});
 assert.equal((await observer('demo')).status,'observed');offline=true;time+=16;
 const stale=await observer('demo');assert.equal(stale.status,'stale');assert.equal(stale.last_success.credit.withdrawable_wei,'0');
 const empty=createChainObserver({demo:selection},{rpc:fixture({fail:true}).rpc});assert.equal((await empty('demo')).status,'unknown');assert.equal((await empty('absent')).status,'not_configured');
});

test('refuses substituted candidate and unselected submission identity',async()=>{await assert.rejects(observeChain({...selection,expected_commitments:{...selection.expected_commitments,candidate:digest('a')}},fixture().rpc));await assert.rejects(observeChain({...selection,expected_commitments:null},fixture().rpc));});
