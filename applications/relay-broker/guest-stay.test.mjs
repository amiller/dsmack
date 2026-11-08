import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet, Interface, keccak256, toUtf8Bytes } from "npm:ethers@6.17.0";
import { Payments } from "./payments.mjs";
import { Inference } from "./inference.mjs";
import { AgentSessions } from "./agent.mjs";
import { canonical, signingKey } from "./grants.mjs";
import { GUEST_ESCROW, LAYC, guestDomain } from "./guest-stay.mjs";
const peer = "12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x";
const abi = new Interface([
 "function terms(address,bytes32) view returns (address operator,uint256 cap,uint64 closedAt,bool released)",
 "function balance(address) view returns (uint256)","function exposure(address) view returns (uint256)",
 "function totalClaimed(address,bytes32) view returns (uint256)",
 "function guestKeys(address) view returns (address operator,bytes32 workload,bytes32 kid,bytes32 cdhash)",
 "function approved(bytes32) view returns (bool)",
]);
const hex = v => [...new Uint8Array(v)].map(v => v.toString(16).padStart(2,"0")).join("");
async function fixture() {
 let now=2000000000;
 const buyer=Wallet.createRandom(),operator=Wallet.createRandom(),guest=Wallet.createRandom();
 const control=await signingKey("34".repeat(32)),brokerKey=await signingKey("12".repeat(32));
 const code="0x6000",word="0x"+"12".repeat(32);
 const terms={kind:"layover-terms/1",mode:"couch",chain_id:84532,escrow:GUEST_ESCROW,token:LAYC,unit:"LAYC",decimals:6,
  thread:"thread-1",publisher:operator.address.toLowerCase(),slot_id:0,operator:operator.address.toLowerCase(),minutes:5,
  rate_layc_per_second:15,minimum_seconds:60,cap:"4500",browse:{mode:"none",hosts:[]},task:"run commands"};
 const acceptedTerms={terms:JSON.stringify(terms),termsHash:keccak256(toUtf8Bytes(JSON.stringify(terms)))};
 const reads={terms:[operator.address,4500n,0n,false],balance:[4500n],exposure:[4500n],totalClaimed:[0n],guestKeys:[operator.address,word,word,word],approved:[true]};
 const chain={snapshot:async()=>({block:{hash:word,number:123},tag:{blockHash:word},read:async(method,[arg])=>{
   if(method==="eth_getCode")return code;
   assert.equal(arg.to,GUEST_ESCROW);
   const fn=abi.getFunction(arg.data.slice(0,10)).name;
   return abi.encodeFunctionResult(fn,reads[fn]);
 }})};
 const payments=new Payments({cfg:{escrow:"0x"+"11".repeat(20)},key:Wallet.createRandom(),chain,state:{},save:async()=>{},now:()=>now});
 const inference=new Inference({payments,cfg:{model:"fixture/model"},provider:{apiKey:"fixture"},now:()=>now});
 const node={kind:"compute",relay_peer:peer,receipt_key:control.public_key,admit_until:now+3600,
  payments:{operator:operator.address,receiptSigner:guest.address,runExpires:now+3600},
  attestation:{nodeBinding:{binding:{receiptSigner:guest.address}}}};
 const broker={payments,inference,key:brokerKey,cfg:{agent:{guestEscrowCodeHash:keccak256(code)}},live:()=>[node],gone:()=>false,now:()=>now};
 const fleet=async()=>[{publisher:operator.address.toLowerCase(),online:true,received_at:now,updated_at:now,
  config:{max_guests:1},slots:[{slot_id:0,state:"ready",relay_peer:peer}]}];
 const sessions=new AgentSessions(broker,fleet);
 const signed=async(action,extra={})=>{const body={action,wallet:buyer.address,nonce:hex(crypto.getRandomValues(new Uint8Array(16))),issuedAt:now,...extra};return {...body,sig:await buyer.signMessage(canonical(body))};};
 const open=async()=>sessions.open(await signed("agent-open",{conversationId:"thread-1",client_peer:peer,node_peer:peer,acceptedTerms}));
 let sequence=0;
 const checkpoint=async(sessionId,used,final=false)=>{
  const owed=String((used?Math.max(60,used):0)*15);
  const signature=await guest.signTypedData(guestDomain(buyer.address),{Claim:[{name:"operator",type:"address"},{name:"termsHash",type:"bytes32"},{name:"cumulativeOwed",type:"uint256"}]},
   {operator:operator.address,termsHash:acceptedTerms.termsHash,cumulativeOwed:owed});
  const claim={escrow:GUEST_ESCROW,key:guest.address,buyer:buyer.address,terms_hash:acceptedTerms.termsHash,operator:operator.address,cumulative_owed:owed,signature};
  const body={sessionId,claim,guestSeconds:used,final,sequence:++sequence,endedAt:now};
  return {...body,controlSignature:hex(await crypto.subtle.sign("Ed25519",control.priv,new TextEncoder().encode(canonical(body))))};
 };
 return {open,sessions,payments,reads,checkpoint,signed,broker,acceptedTerms,advance:s=>now+=s};
}

test("funded couch starts with no credit account and relays the guest claim without a financial ledger",async()=>{
 const f=await fixture(),s=await f.open();
 assert.equal(s.credit,undefined);assert.equal(s.rateLaycPerSecond,15);
 assert.deepEqual(s.grant.escrow,{buyer:f.payments.state.agentSessions[s.sessionId].wallet,terms:f.acceptedTerms.terms,termsHash:f.acceptedTerms.termsHash});
 await f.sessions.receipt(await f.checkpoint(s.sessionId,0));
 f.advance(5);
 const r=await f.checkpoint(s.sessionId,5,true);
 await f.sessions.receipt(r);await f.sessions.receipt(r);
 const view=await f.sessions.status(await f.signed("agent-status",{sessionId:s.sessionId}));
 assert.equal(view.claim.cumulative_owed,"900");assert.equal(view.active,false);assert.deepEqual(view.claim,r.claim);
 assert.equal(f.payments.state.inferenceCredit,undefined);assert.equal(f.payments.state.operatorAccruals,undefined);
});

test("unfunded terms and unregistered or revoked guest keys cannot open a stay",async()=>{
 for(const [field,value] of [["balance",[0n]],["terms",["0x"+"00".repeat(20),4500n,0n,false]],["guestKeys",["0x"+"00".repeat(20),"0x"+"12".repeat(32),"0x"+"12".repeat(32),"0x"+"12".repeat(32)]],["approved",[false]]]){
  const f=await fixture();f.reads[field]=value;
  await assert.rejects(f.open(),e=>e.code==="GUEST_ESCROW");
  assert.equal(f.payments.state.agentSessions,undefined);assert.equal(f.payments.state.inferenceCredit,undefined);
 }
});

test("tampered final flags and claims cannot stop or charge an active couch",async()=>{
 const f=await fixture(),s=await f.open();
 const r=await f.checkpoint(s.sessionId,0);
 await assert.rejects(f.sessions.receipt({...r,final:true}),e=>e.code==="GUEST_ESCROW");
 await f.sessions.receipt(r);
 const next=await f.checkpoint(s.sessionId,1);
 next.claim.cumulative_owed="4501";
 await assert.rejects(f.sessions.receipt(next),e=>e.code==="GUEST_ESCROW");
 assert.equal(f.payments.state.agentSessions[s.sessionId].guestSeconds,0);
});
