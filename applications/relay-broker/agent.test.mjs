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
 const sessions=new AgentSessions(broker);
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
 return {sessions,inference,payments,signed,open,receipt,other,advance:(s)=>now+=s};
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
