import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "npm:ethers@6.17.0";
import { Payments } from "./payments.mjs";
import { Inference } from "./inference.mjs";
import { AgentSessions } from "./agent.mjs";
import { canonical, signingKey } from "./grants.mjs";
const hex = (v) => [...new Uint8Array(v)].map(v => v.toString(16).padStart(2,"0")).join("");
const peer = "12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x";
async function fixture() {
 let now=2000000000;
 const wallet=Wallet.createRandom(), other=Wallet.createRandom();
 const key=await signingKey("12".repeat(32));
 const receiptKey=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const receipt_key=hex(await crypto.subtle.exportKey("raw",receiptKey.publicKey));
 const payments=new Payments({cfg:{},key:{},quorum:{},state:{},save:async()=>{},now:()=>now});
 const inference=new Inference({payments,cfg:{model:"fixture/model"},provider:{apiKey:"fixture"},now:()=>now});
 const node={kind:"compute",relay_peer:peer,receipt_key,admit_until:now+1800};
 const broker={payments,inference,key,cfg:{},live:()=>[node],now:()=>now};
 let fleetSlots;
 const readFleet=async()=>[{publisher:"mac-one",online:true,received_at:now,updated_at:now,
  slots:fleetSlots??broker.live().map((n,slot_id)=>({slot_id,state:"ready",relay_peer:n.relay_peer}))}];
 const sessions=new AgentSessions(broker,readFleet);
 async function signed(action,extra={},who=wallet) {
  const body={action,wallet:who.address,nonce:crypto.randomUUID().replaceAll("-",""),issuedAt:now,...extra};
  return {...body,sig:await who.signMessage(canonical(body))};
 }
 await inference.credit(await signed("credit"));
 async function open(who=wallet) {return sessions.open(await signed("agent-open",{conversationId:"conversation",client_peer:peer,node_peer:peer},who));}
 async function receipt(sessionId,guestSeconds,final=false,wrongKey=false) {
  const body={sessionId,node_peer:peer,guestSeconds,final};
  const key=wrongKey?(await crypto.subtle.generateKey("Ed25519",true,["sign","verify"])).privateKey:receiptKey.privateKey;
  return {...body,sig:hex(await crypto.subtle.sign("Ed25519",key,new TextEncoder().encode(canonical(body))))};
 }
 return {sessions,inference,payments,signed,open,receipt,other,wallet,broker,node,readFleet,
  setSlots:value=>{fleetSlots=value;},advance:(s)=>now+=s};
}

test("guest seconds reserve and settle the same credit; untrusted reports cannot charge it",async()=>{
 const f=await fixture(),session=await f.open();
 assert.equal(session.credit.reservedNanoUsd,"18000000");
 assert.equal(session.credit.remainingNanoUsd,"232000000");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,5,false,true)),e=>e.code==="GUEST_SIGNATURE");
 await f.sessions.receipt(await f.receipt(session.sessionId,5));
 let status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.guestSeconds,5);
 assert.equal(status.credit.spentNanoUsd,"50000");
 assert.equal(status.credit.reservedNanoUsd,"17950000");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,4)),e=>e.code==="GUEST_USAGE");
 await assert.rejects(f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId},f.other),true),e=>e.code==="CREDIT_NOT_CONFIRMED");
 await f.inference.credit(await f.signed("credit",{},f.other));
 await assert.rejects(f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId},f.other),true),e=>e.code==="SESSION_OWNER");
 const ended=await f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId}),true);
 assert.equal(ended.endRequested,true);
 assert.equal((await f.sessions.receipt(await f.receipt(session.sessionId,7))).stop,true);
 const final=await f.receipt(session.sessionId,8,true);
 await f.sessions.receipt(final); await f.sessions.receipt(final);
 status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.active,false);
 assert.equal(status.credit.spentNanoUsd,"80000");
 assert.equal(status.credit.reservedNanoUsd,"0");
});

test("concurrent claims hold one guest and expired unused grants release without invented usage",async()=>{
 const f=await fixture();
 const results=await Promise.allSettled([f.open(),f.open()]);
 assert.equal(results.filter(r=>r.status==="fulfilled").length,1);
 const first=results.find(r=>r.status==="fulfilled").value;
 f.advance(1801);
 const status=await f.sessions.status(await f.signed("agent-status",{sessionId:first.sessionId}));
 assert.equal(status.active,false);
 assert.equal(status.credit.reservedNanoUsd,"0");
 assert.equal(status.credit.spentNanoUsd,"0");
});

test("ending before transport admission releases credit and revokes the unused grant",async()=>{
 const f=await fixture(),session=await f.open();
 const ended=await f.sessions.status(await f.signed("agent-end",{sessionId:session.sessionId}),true);
 assert.equal(ended.active,false);
 assert.equal(ended.credit.reservedNanoUsd,"0");
 assert.equal(ended.credit.spentNanoUsd,"0");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,0)),e=>e.code==="SESSION_CLOSED");
 assert.notEqual((await f.open()).sessionId,session.sessionId);
});

test("expired started session releases ownership and preserves unresolved credit until signed final recovery",async()=>{
 const f=await fixture(),session=await f.open();
 await f.sessions.receipt(await f.receipt(session.sessionId,5));
 f.advance(1801);
 let status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.usageUnresolved,true);
 assert.equal(status.credit.reservedNanoUsd,"17950000");
 await f.sessions.receipt(await f.receipt(session.sessionId,6,true));
 status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.usageUnresolved,false);
 assert.equal(status.credit.reservedNanoUsd,"0");
 assert.equal(status.credit.spentNanoUsd,"60000");
});

test("four payout guests advertise distinct availability and a fifth claim is busy",async()=>{
 const f=await fixture();
 const nodes=Array.from({length:4},(_,i)=>({...f.node,relay_peer:peer+"-slot-"+i,telemetry:{busy:false}}));
 f.broker.live=()=>nodes;
 const wallets=[f.wallet,Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom(),f.other];
 for(const wallet of wallets.slice(1))await f.inference.credit(await f.signed("credit",{},wallet));
 const held=[];
 for(const [i,wallet] of wallets.slice(0,4).entries()){
  const node=nodes.find(n=>f.sessions.available(n));
  assert(node,"slot "+i+" should be available");
  const session=await f.sessions.open(await f.signed("agent-open",{conversationId:"conversation-"+i,client_peer:peer,node_peer:node.relay_peer},wallet));
  held.push(session.node.relay_peer);
  assert.equal(f.sessions.available(node),false);
 }
 assert.equal(new Set(held).size,4);
 assert.equal(nodes.filter(n=>f.sessions.available(n)).length,0);
 await assert.rejects(f.sessions.open(await f.signed("agent-open",{conversationId:"fifth",client_peer:peer,node_peer:nodes[0].relay_peer},wallets[4])),e=>e.code==="GUEST_BUSY");
 f.advance(1801);
 assert.equal(f.sessions.available(nodes[0]),true);
 nodes[0].telemetry.busy=true;
 assert.equal(f.sessions.available(nodes[0]),false,"guest status remains authoritative after a lease expires");
});


test("a held predecessor keeps its logical slot when a ready replacement appears",async()=>{
 const f=await fixture(),first=await f.open();
 assert.deepEqual(f.payments.state.agentSessions[first.sessionId].placement,{publisher:"mac-one",slot_id:0});
 const replacement={...f.node,relay_peer:peer+"-replacement",admit_until:f.node.admit_until+100};
 f.broker.live=()=>[f.node,replacement];
 f.setSlots([{slot_id:0,state:"ready",relay_peer:f.node.relay_peer},
  {slot_id:0,state:"ready",relay_peer:replacement.relay_peer}]);
 await f.inference.credit(await f.signed("credit",{},f.other));
 async function replacementClaim(){return await f.signed("agent-open",{conversationId:"replacement",client_peer:peer,
  node_peer:replacement.relay_peer},f.other);}
 await assert.rejects(f.sessions.open(await replacementClaim()),e=>e.code==="GUEST_BUSY");
 // The persisted slot also blocks a replacement after the old guest is absent
 // from the new heartbeat and live node index.
 f.broker.live=()=>[replacement];
 f.setSlots([{slot_id:0,state:"ready",relay_peer:replacement.relay_peer}]);
 await assert.rejects(f.sessions.open(await replacementClaim()),e=>e.code==="GUEST_BUSY");
 const reloaded=new AgentSessions(f.broker,f.readFleet);
 await assert.rejects(reloaded.open(await replacementClaim()),e=>e.code==="GUEST_BUSY");
 await f.sessions.status(await f.signed("agent-end",{sessionId:first.sessionId}),true);
 const resumed=await reloaded.open(await replacementClaim());
 assert.deepEqual(resumed.placement,{publisher:"mac-one",slot_id:0});
});

test("four different logical slots admit concurrently and a fifth direct claim cannot take a spare",async()=>{
 const f=await fixture();
 const nodes=Array.from({length:4},(_,i)=>({...f.node,relay_peer:peer+"-logical-"+i}));
 f.broker.live=()=>nodes;
 const wallets=[f.wallet,Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom(),f.other];
 for(const wallet of wallets.slice(1))await f.inference.credit(await f.signed("credit",{},wallet));
 const requests=await Promise.all(wallets.slice(0,4).map((wallet,i)=>f.signed("agent-open",{
  conversationId:"logical-"+i,client_peer:peer,node_peer:nodes[i].relay_peer},wallet)));
 const held=await Promise.all(requests.map(request=>f.sessions.open(request)));
 assert.equal(new Set(held.map(session=>session.placement.slot_id)).size,4);
 const spare={...f.node,relay_peer:peer+"-spare",admit_until:f.node.admit_until+100};
 f.broker.live=()=>nodes.concat(spare);
 f.setSlots(nodes.map((node,slot_id)=>({slot_id,state:"ready",relay_peer:node.relay_peer}))
  .concat({slot_id:0,state:"ready",relay_peer:spare.relay_peer}));
 await assert.rejects(f.sessions.open(await f.signed("agent-open",{conversationId:"fifth-spare",client_peer:peer,
  node_peer:spare.relay_peer},wallets[4])),e=>e.code==="GUEST_BUSY");
 assert.equal(Object.values(f.payments.state.agentSessions).filter(session=>!session.final).length,4);
});
