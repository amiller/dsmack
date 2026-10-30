import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "npm:ethers@6.17.0";
import { Payments } from "./payments.mjs";
import { Inference, creditGrantPrefix } from "./inference.mjs";
import { AgentSessions } from "./agent.mjs";
import { canonical, signingKey } from "./grants.mjs";
const hex = (v) => [...new Uint8Array(v)].map(v => v.toString(16).padStart(2,"0")).join("");
const peer = "12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x";
async function fixture({ starter = "250000000", lifetime = 1800 } = {}) {
 let now=2000000000;
 const wallet=Wallet.createRandom(), other=Wallet.createRandom();
 const key=await signingKey("12".repeat(32));
 const receiptKey=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const receipt_key=hex(await crypto.subtle.exportKey("raw",receiptKey.publicKey));
 const payments=new Payments({cfg:{},key:{},quorum:{},state:{},save:async()=>{},now:()=>now});
 const inference=new Inference({payments,cfg:{model:"fixture/model",starterCreditNanoUsd:starter},provider:{apiKey:"fixture"},now:()=>now});
 const node={kind:"compute",relay_peer:peer,receipt_key,admit_until:now+lifetime};
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
 async function receipt(sessionId,guestSeconds,final=false,wrongKey=false,closedReason=undefined) {
  const body={sessionId,node_peer:peer,guestSeconds,final,...(closedReason?{closedReason}:{})};
  const key=wrongKey?(await crypto.subtle.generateKey("Ed25519",true,["sign","verify"])).privateKey:receiptKey.privateKey;
  return {...body,sig:hex(await crypto.subtle.sign("Ed25519",key,new TextEncoder().encode(canonical(body))))};
 }
 return {sessions,inference,payments,signed,open,receipt,other,wallet,broker,node,readFleet,
  setSlots:value=>{fleetSlots=value;},advance:(s)=>now+=s};
}

test("guest seconds reserve and settle the same credit; untrusted reports cannot charge it",async()=>{
 const f=await fixture(),session=await f.open();
 assert.equal(session.credit.reservedNanoUsd,"300000");
 assert.equal(session.credit.remainingNanoUsd,"249700000");
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,5,false,true)),e=>e.code==="GUEST_SIGNATURE");
 await f.sessions.receipt(await f.receipt(session.sessionId,5));
 let status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.guestSeconds,5);
 assert.equal(status.credit.spentNanoUsd,"50000");
 assert.equal(status.credit.reservedNanoUsd,"300000");
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
 assert.equal(status.credit.reservedNanoUsd,"300000");
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


test("active seconds replenish one grant beyond the old half-credit cutoff and idle wall time is not charged",async()=>{
 const f=await fixture({starter:"1000000",lifetime:3600}),session=await f.open();
 assert.equal(session.grant.seconds,3600);assert.equal(session.activeBudgetSeconds,30);
 const grant=session.grant;
 await f.sessions.receipt(await f.receipt(session.sessionId,0));
 f.advance(300);
 assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).spentNanoUsd,"0");
 for(const used of [20,40,60,80]){
  const receipt=await f.sessions.receipt(await f.receipt(session.sessionId,used));
  assert.equal(receipt.stop,false);
  assert(receipt.activeBudgetSeconds>used);
 }
 assert.equal(Object.keys(f.payments.state.agentSessions).length,1);
 assert.deepEqual(f.payments.state.agentSessions[session.sessionId].grant,grant);
 const exhausted=await f.sessions.receipt(await f.receipt(session.sessionId,100));
 assert.equal(exhausted.stop,true);assert.equal(exhausted.reason,"credit");
 assert.equal(exhausted.activeBudgetSeconds,100);
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,101)),e=>e.code==="GUEST_USAGE");
 await f.sessions.receipt(await f.receipt(session.sessionId,100,true));
 assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).spentNanoUsd,"1000000");
 assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).reservedNanoUsd,"0");
 await assert.rejects(f.open(),e=>e.code==="CREDIT_EXHAUSTED");
});

test("rolling reservations protect an in-flight model budget and final idle release returns unused seconds",async()=>{
 const f=await fixture({starter:"1000000"}),session=await f.open(),wallet=f.wallet.address.toLowerCase();
 // This is the same pending ledger state persisted by Inference.chat before
 // dispatch. A concurrent guest checkpoint cannot consume its model budget.
 f.payments.state.inferenceCredit[wallet].pending="model";
 f.payments.state.inferenceRequests={model:{status:"sent",reservedNanoUsd:"600000"}};
 const updated=await f.sessions.receipt(await f.receipt(session.sessionId,20));
 assert.equal(updated.activeBudgetSeconds,40);
 assert.equal(f.inference.summary(wallet).remainingNanoUsd,"0");
 assert.equal(f.payments.state.inferenceRequests.model.reservedNanoUsd,"600000");
 const final=await f.sessions.receipt(await f.receipt(session.sessionId,20,true));
 assert.equal(final.stop,true);
 assert.equal(f.inference.summary(wallet).spentNanoUsd,"200000");
 assert.equal(f.inference.summary(wallet).reservedNanoUsd,"600000");
});

test("explicit gift credit resumes on a new grant after a credit stop, without reviving the ending stay",async()=>{
 const f=await fixture({starter:"200000"}),session=await f.open();
 assert.equal(session.activeBudgetSeconds,20);
 assert.equal((await f.sessions.receipt(await f.receipt(session.sessionId,20))).reason,"credit");
 const issuer=Wallet.createRandom(),escrow="0x"+"81".repeat(20);
 const grant={v:1,chainId:84532,escrow,brokerKey:f.broker.key.public_key,wallet:f.wallet.address,
  amountNanoUsd:"200000",nonce:"ab".repeat(32),expiresAt:f.broker.now()+600};
 await f.inference.grantCredit({grant,signature:await issuer.signMessage(creditGrantPrefix+canonical(grant))},
  {issuer:issuer.address,escrow,brokerKey:f.broker.key.public_key});
 const ending=await f.sessions.receipt(await f.receipt(session.sessionId,20));
 assert.equal(ending.stop,true);assert.equal(ending.reason,"credit");
 await f.sessions.receipt(await f.receipt(session.sessionId,20,true));
 const replacement={...f.node,relay_peer:peer+"-after-credit"};f.broker.live=()=>[replacement];
 const resumed=await f.sessions.open(await f.signed("agent-open",{conversationId:"conversation",client_peer:peer,node_peer:replacement.relay_peer}));
 assert.notEqual(resumed.sessionId,session.sessionId);
 assert.equal(resumed.activeBudgetSeconds,20);
 assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).spentNanoUsd,"200000");
});


test("unused setup grants release after 90 seconds while wall expiry leaves room for an admitted call",async()=>{
 const f=await fixture({lifetime:3300});f.node.payments={runExpires:f.broker.now()+3600};
 const session=await f.open();
 assert.equal(session.handoverAt,f.node.admit_until);
 assert.equal(session.grant.expires_at,f.broker.now()+3480);
 assert.equal(session.setupUntil,f.broker.now()+90);
 f.advance(91);
 assert.equal(f.sessions.available(f.node),true);
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,0)),e=>e.code==="SESSION_CLOSED");
 const status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.active,false);assert.equal(status.closedReason,"unused-grant-expired");
 assert.equal(status.credit.spentNanoUsd,"0");assert.equal(status.credit.reservedNanoUsd,"0");
});


test("a signed final idle reason releases an unbilled stay; checkpoints cannot supply close reasons",async()=>{
 const f=await fixture(),session=await f.open();
 await f.sessions.receipt(await f.receipt(session.sessionId,0));
 await assert.rejects(f.sessions.receipt(await f.receipt(session.sessionId,0,false,false,"idle")),e=>e.code==="BAD_REQUEST");
 f.advance(300);
 const final=await f.sessions.receipt(await f.receipt(session.sessionId,0,true,false,"idle"));
 assert.equal(final.activeBudgetSeconds,session.activeBudgetSeconds,"final reply keeps the authorized counter monotonic");
 const status=await f.sessions.status(await f.signed("agent-status",{sessionId:session.sessionId}));
 assert.equal(status.closedReason,"idle");assert.equal(status.active,false);
 assert.equal(status.credit.spentNanoUsd,"0");assert.equal(status.credit.reservedNanoUsd,"0");
});


test("late original full-reservation receipts remain payable after rolling budgets are introduced",async()=>{
 const f=await fixture(),session=await f.open(),record=f.payments.state.agentSessions[session.sessionId];
 // Original persisted stays predate the rolling budget and setup deadline.
 delete record.activeBudgetSeconds;delete record.setupUntil;
 record.reservedNanoUsd=String(BigInt(record.grant.seconds)*BigInt(record.rateNanoUsdPerSecond));
 await f.sessions.receipt(await f.receipt(session.sessionId,700));
 assert.equal(record.grant.seconds,1800);
 assert.equal(f.payments.state.agentSessions[session.sessionId].activeBudgetSeconds,undefined);
 assert.equal(f.payments.state.agentSessions[session.sessionId].reservedNanoUsd,"11000000");
 await f.sessions.receipt(await f.receipt(session.sessionId,1600,true));
 const credit=f.inference.summary(f.wallet.address.toLowerCase());
 assert.equal(credit.spentNanoUsd,"16000000");assert.equal(credit.reservedNanoUsd,"0");
});
