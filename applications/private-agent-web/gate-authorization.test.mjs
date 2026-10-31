import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Interface } from 'ethers';
import { createGateAuthorization } from './gate-authorization.mjs';

const abi = new Interface(['function isAppAllowed(tuple(address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds)) view returns (bool,string)']);
const policy = { chainId: 8453, kms: '0x'+'11'.repeat(20), rpcs: ['https://rpc-one.test', 'https://rpc-two.test'] };
const boot = { appId:'0x'+'22'.repeat(20),composeHash:'0x'+'33'.repeat(32),instanceId:'0x'+'44'.repeat(20),deviceId:'0x'+'55'.repeat(32),mrAggregated:'0x'+'66'.repeat(32),mrSystem:'0x'+'77'.repeat(32),osImageHash:'0x'+'88'.repeat(32),tcbStatus:'UpToDate',advisoryIds:[] };
function fixture() {
  let time=1_800_000_000_000;
  const state={allowed:true,calls:[],fail:false,wrongChain:false,disagree:false,otherBlock:false,stale:false};
  const verify=createGateAuthorization({now:()=>time,fetcher:async(url,options)=>{
    if(state.fail)throw TypeError('Failed to fetch');
    const {method,params}=JSON.parse(options.body);state.calls.push({url,method,params});
    const second=url===policy.rpcs[1];let result;
    if(method==='eth_chainId')result=state.wrongChain&&second?'0x1':'0x2105';
    if(method==='eth_blockNumber')result=second?'0x102':'0x100';
    if(method==='eth_getBlockByNumber')result={number:params[0],hash:'0x'+(state.otherBlock&&second?'bb':'aa').repeat(32),timestamp:'0x'+Math.floor((time-(state.stale?180000:0))/1000).toString(16)};
    if(method==='eth_call')result=abi.encodeFunctionResult('isAppAllowed',[state.disagree&&second?!state.allowed:state.allowed,'']);
    return new Response(JSON.stringify({jsonrpc:'2.0',id:1,result}));
  }});
  return {state,verify,advance:ms=>time+=ms};
}
test('both RPCs authorize the complete boot identity at one matching block',async()=>{
  const f=fixture(),e=await f.verify(boot,policy);
  assert.equal(e.blockNumber,256);assert.deepEqual(e.providers,policy.rpcs);
  const calls=f.state.calls.filter(c=>c.method==='eth_call');assert.equal(calls.length,2);
  for(const {params} of calls){assert.equal(params[0].to,policy.kms);assert.equal(params[1],'0x100');const actual=abi.decodeFunctionData('isAppAllowed',params[0].data)[0];for(const [k,v] of Object.entries(boot))assert.deepEqual(Array.isArray(v)?Array.from(actual[k]):actual[k],v);}
});
test('authorization cache expires after 30 seconds so revocation is enforced',async()=>{
  const f=fixture();await f.verify(boot,policy);const count=f.state.calls.length;
  f.state.allowed=false;f.advance(29999);await f.verify(boot,policy);assert.equal(f.state.calls.length,count);
  f.advance(1);await assert.rejects(f.verify(boot,policy),{code:'RECOVERY_NOT_AUTHORIZED'});
});
test('a different compose or device never reuses another authorization',async()=>{
  const f=fixture();await f.verify(boot,policy);f.state.allowed=false;
  await assert.rejects(f.verify({...boot,composeHash:'0x'+'99'.repeat(32)},policy),{code:'RECOVERY_NOT_AUTHORIZED'});
  await assert.rejects(f.verify({...boot,deviceId:'0x'+'99'.repeat(32)},policy),{code:'RECOVERY_NOT_AUTHORIZED'});
});
test('unavailable, inconsistent, stale and wrong-chain RPCs fail closed and do not cache',async t=>{
  for(const key of ['fail','wrongChain','disagree','otherBlock','stale'])await t.test(key,async()=>{
    const f=fixture();f.state[key]=true;
    await assert.rejects(f.verify(boot,policy),{code:'RECOVERY_CHAIN_UNAVAILABLE'});
    f.state[key]=false;assert.equal((await f.verify(boot,policy)).chainId,8453);
  });
});
test('a shared RPC host is not treated as two independent providers',async()=>{
  const f=fixture();await assert.rejects(f.verify(boot,{...policy,rpcs:[policy.rpcs[0],policy.rpcs[0]+'/other']}),{code:'RECOVERY_CHAIN_UNAVAILABLE'});assert.equal(f.state.calls.length,0);
});
