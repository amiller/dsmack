import assert from "node:assert/strict";
import { test } from "node:test";
import { FetchRequest, JsonRpcProvider, Wallet } from "../payments/schema.mjs";
import { canonical, signingKey } from "./grants.mjs";
import { Continuity, cidFor, decode, headDigest, anchorReceipt } from "./continuity.mjs";
const encode = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
async function fixture() {
  const wallet=Wallet.createRandom(), stranger=Wallet.createRandom(),key=await signingKey("11".repeat(32));
  const pins=new Map(),chainState=new Map();let saved;
  const chain={
    async heads(wallet){return chainState.get(wallet)??{counter:0n,digest:"0x"+"00".repeat(32)};},
    async commit(wallet,previous,digest){const head=await this.heads(wallet);assert.equal(Number(head.counter),previous);chainState.set(wallet,{counter:BigInt(previous+1),digest});return {hash:"0x"+"22".repeat(32)};},
  };
  let receipt=async()=>({status:1});
  const broker=new Continuity({receipt:(hash)=>receipt(hash),cfg:{anchor:"0x"+"33".repeat(20)},key,anchorKey:{},chain,save:async s=>saved=structuredClone(s),put:async(k,v)=>pins.set(k,v),get:async k=>pins.get(k)});
  async function request(action,fields={},who=wallet){const r={action:"sync-"+action.replaceAll("/","-"),wallet:who.address,nonce:crypto.randomUUID().replaceAll("-",""),issuedAt:Math.floor(Date.now()/1000),...fields};r.sig=await who.signMessage(canonical(r));return r;}
  return {wallet,stranger,key,broker,chain,chainState,pins,request,setReceipt:(fn)=>{receipt=fn;},get saved(){return saved;}};
}
test("ciphertext pins verify CIDs, signatures prevent another wallet's commits, and head CAS prevents lost writes",async()=>{
 const f=await fixture(),ciphertext=encode(crypto.getRandomValues(new Uint8Array(64))),blob=await f.broker.call("blob",await f.request("blob",{ciphertext}));
 assert.equal(blob.cid,await cidFor(decode(ciphertext)));assert.equal((await f.broker.call("read",await f.request("read",blob))).ciphertext,ciphertext);
 const commit=await f.request("commit",{previous:0,cid:blob.cid});const result=await f.broker.call("commit",commit);
 assert.equal(result.head.counter,1);assert.equal((await f.chain.heads(f.wallet.address.toLowerCase())).digest,headDigest(result.head));
 assert.equal((await f.broker.call("head",await f.request("head"))).head.counter,1);
 await assert.rejects(f.broker.call("commit",commit),/replayed/);
 await assert.rejects(f.broker.call("commit",await f.request("commit",{previous:0,cid:blob.cid})),/head changed/);
 const forged=await f.request("head",{},f.stranger);forged.wallet=f.wallet.address;
 await assert.rejects(f.broker.call("head",forged),/signature/);
 f.pins.set(blob.cid,encode(new Uint8Array(64)));await assert.rejects(f.broker.call("read",await f.request("read",blob)),/CID mismatch/);
});
test("on-chain state detects restored old broker heads and wrap writes require credential ownership",async()=>{
 const f=await fixture(),ciphertext=encode(crypto.getRandomValues(new Uint8Array(64))),blob=await f.broker.call("blob",await f.request("blob",{ciphertext}));
 await f.broker.call("commit",await f.request("commit",{previous:0,cid:blob.cid}));
 f.chainState.set(f.wallet.address.toLowerCase(),{counter:2n,digest:"0x"+"44".repeat(32)});
 await assert.rejects(f.broker.call("head",await f.request("head")),/differs from chain anchor/);
 const credentialId="a".repeat(43),envelope={ciphertext};await f.broker.call("wrap/put",await f.request("wrap/put",{credentialId,envelope}));
 assert.deepEqual((await f.broker.call("wrap/get",{credentialId})).envelope,envelope);
 await assert.rejects(f.broker.call("wrap/put",await f.request("wrap/put",{credentialId,envelope},f.stranger)),/another wallet/);
});
test("head reads wait for a pending anchor transaction instead of observing its unmined candidate",async()=>{
 const f=await fixture(),ciphertext=encode(crypto.getRandomValues(new Uint8Array(64))),blob=await f.broker.call("blob",await f.request("blob",{ciphertext}));
 let release,started;const mining=new Promise(r=>release=r),waiting=new Promise(r=>started=r);
 f.setReceipt(async()=>{started();await mining;return {status:1};});
 const committed=f.broker.call("commit",await f.request("commit",{previous:0,cid:blob.cid}));await waiting;
 let observed=false;const read=f.broker.call("head",await f.request("head")).then(r=>{observed=true;return r;});
 await new Promise(r=>setTimeout(r,10));assert.equal(observed,false);
 release();await committed;assert.equal((await read).head.counter,1);
});
test("a reverted anchor commit restores the previous broker head",async()=>{
 const f=await fixture(),ciphertext=encode(crypto.getRandomValues(new Uint8Array(64))),blob=await f.broker.call("blob",await f.request("blob",{ciphertext}));
 f.setReceipt(async()=>{f.chainState.delete(f.wallet.address.toLowerCase());throw Object.assign(new Error("sync anchor transaction reverted"),{status:503});});
 await assert.rejects(f.broker.call("commit",await f.request("commit",{previous:0,cid:blob.cid})),/reverted/);
 assert.deepEqual(await f.broker.call("head",await f.request("head")),{head:null});
 f.setReceipt(async()=>({status:1}));
 assert.equal((await f.broker.call("commit",await f.request("commit",{previous:0,cid:blob.cid}))).head.counter,1);
});

test("anchor receipt polling awaits rate-limit recovery without block subscriptions and reports exhausted RPC errors", async()=>{
 const hash="0x"+"55".repeat(32),calls=[],delays=[];let attempt=0;
 const server=Deno.serve({hostname:"127.0.0.1",port:0,onListen(){}},async request=>{
   const r=await request.json();calls.push(r.method);assert.deepEqual(r.params,[hash]);attempt++;
   return Response.json(attempt===1?{jsonrpc:"2.0",id:r.id,error:{code:-32007,message:"25/second request limit reached"}}:{jsonrpc:"2.0",id:r.id,result:attempt===2?null:{transactionHash:hash,status:"0x1"}});
 });
 const provider=new JsonRpcProvider(new FetchRequest("http://127.0.0.1:"+server.addr.port),84532,{staticNetwork:true,cacheTimeout:-1,batchMaxCount:1});
 try {
   const receipt=await anchorReceipt(provider,hash,{sleep:async ms=>delays.push(ms)});
   assert.equal(receipt.status,"0x1");assert.deepEqual(calls,["eth_getTransactionReceipt","eth_getTransactionReceipt","eth_getTransactionReceipt"]);assert.deepEqual(delays,[2000,4000]);
   assert.equal(await provider.listenerCount("block"),0);assert.equal(await provider.listenerCount(hash),0);
 } finally { provider.destroy();await server.shutdown(); }
 await assert.rejects(anchorReceipt({send:async()=>{throw Object.assign(new Error("25/second request limit reached"),{code:-32007});}},hash,{attempts:2,sleep:async()=>{}}),error=>error.status===503&&error.message.includes("25/second request limit reached"));
 const f=await fixture();f.chain.heads=async()=>{throw Object.assign(new Error("25/second request limit reached"),{code:-32007});};
 await assert.rejects(f.broker.call("head",await f.request("head")),error=>error.status===503&&error.message.includes("25/second request limit reached"));
});
