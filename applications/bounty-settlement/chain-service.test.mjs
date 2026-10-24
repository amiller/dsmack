import test from 'node:test';
import assert from 'node:assert/strict';
import {taskChainReader} from './chain-service.mjs';
import {createApplication} from '../bounty-demo/server.mjs';
const a=n=>'0x'+String(n).repeat(40),h=n=>String(n).repeat(64);
const task={id:'demo',terms_sha256:h(1),checker_sha256:h(2)};
const selection={chain_id:84532,escrow:a(1),runtime_sha256:'dd3596a61b94402a0161b950319d726fed7ffd0fd384774fa562d07b06aa6daa',task_id:'1',assignment_id:'1',requester:a(2),worker:a(3),account:a(3),expected_commitments:null,terms:{packageHash:'0x'+h(1),policyHash:'0x'+h(2),allocator:a(2),executionVerifier:a(4),reviewer:a(5),deliveryVerifier:a(6),adjudicator:a(7),effortPay:'0',completionPay:'10',submitSeconds:'300',reviewSeconds:'60',adjudicationSeconds:'60'},minimum_confirmations:2,transactions:[]};
test('task mapping binds current frozen terms, policy and worker; never makes RPC on mismatch',async()=>{
 let calls=0;const store={detail:()=>({task,attempt:{payee:a(4)}})};
 const reader=taskChainReader(store,{demo:selection},{rpc:async()=>{calls++;throw Error('unexpected');}});
 await assert.rejects(reader('demo'));assert.equal(calls,0);
 for(const field of ['terms_sha256','checker_sha256']){const changed={...task,[field]:h(9)};await assert.rejects(taskChainReader({detail:()=>({task:changed})},{demo:selection},{rpc:async()=>{calls++;}})('demo'));}assert.equal(calls,0);
 assert.deepEqual(await taskChainReader({detail:()=>({task})},{})('demo'),{status:'not_configured'});
});
test('loopback chain route is read-only and cannot substitute a selector or verdict',async()=>{
 let observed=[];const store={task:id=>{assert.equal(id,'demo');return task;},detail:()=>({task})};
 const server=createApplication({store,operatorToken:'synthetic-operator-token-1234567890',chainObservation:async id=>{observed.push(id);return {status:'unknown'};}});
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));const url='http://127.0.0.1:'+server.address().port;
 try{
  const r=await fetch(url+'/api/tasks/demo/chain');assert.equal(r.status,200);assert.deepEqual(await r.json(),{status:'unknown'});
  assert.equal((await fetch(url+'/api/tasks/demo/chain?escrow='+a(9))).status,400);
  assert.equal((await fetch(url+'/api/tasks/demo/chain',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status,404);
  assert.deepEqual(observed,['demo']);
 }finally{await new Promise(ok=>server.close(ok));}
});
