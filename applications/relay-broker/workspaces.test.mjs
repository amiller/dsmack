import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet, verifyMessage } from "../payments/schema.mjs";
import { canonical } from "./grants.mjs";
import { canonicalFleet } from "./fleet.mjs";
import { cidFor } from "./continuity.mjs";
import { Workspaces, workspaceChunkBytes, maxEncryptedSnapshotBytes } from "./workspaces.mjs";
const zero = "0".repeat(64), mac = "0x" + "12".repeat(20), peer = "attested-guest", workspaceId = "conversation-one";
const hex = value => [...new Uint8Array(value)].map(v => v.toString(16).padStart(2,"0")).join("");
const digest = async value => hex(await crypto.subtle.digest("SHA-256", value));
const b64 = value => btoa(String.fromCharCode(...value));
async function fixture() {
  const wallet = Wallet.createRandom(), other = Wallet.createRandom(), paymentKey = Wallet.createRandom();
  const receipt = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const session = { wallet: wallet.address.toLowerCase(), conversationId: workspaceId, placement: {publisher:mac,slot_id:0},
    endRequested:true, final:false, node:{relay_peer:peer,receipt_key:hex(await crypto.subtle.exportKey("raw",receipt.publicKey))} };
  const broker = {payments:{key:paymentKey,state:{agentSessions:{stay:session}}}};
  const uploads = new Map(), committed = new Map(); let calls = [], saved = {};
  const store = async (owner, op, body) => {
    calls.push({owner,op,body});
    if(op === "begin") {
      const prior=committed.get(body.head.version);
      if(prior)return {committed:true,head:prior.head,offset:prior.data.length};
      if(!uploads.has(body.uploadId))uploads.set(body.uploadId,{head:body.head,data:new Uint8Array()});
      return {offset:uploads.get(body.uploadId).data.length};
    }
    if(op === "chunk") {
      const pending=uploads.get(body.uploadId), raw=Uint8Array.from(atob(body.data),c=>c.charCodeAt(0));
      const next=new Uint8Array(Math.max(pending.data.length,body.offset+raw.length));
      next.set(pending.data);next.set(raw,body.offset);pending.data=next;return {offset:next.length};
    }
    if(op === "commit") {
      const pending=uploads.get(body.uploadId);assert.equal(await digest(pending.data),pending.head.hash);
      const head={...pending.head,cid:await cidFor(pending.data)};committed.set(head.version,{head,data:pending.data});return {head};
    }
    const snapshot=committed.get(body.head.version), data=snapshot.data.slice(body.offset,body.offset+body.length);
    return {head:snapshot.head,data:b64(data),offset:body.offset,nextOffset:body.offset+data.length,source:"mac",ipfsFetched:false};
  };
  const options={broker,cfg:{stores:{[mac]:"https://store.example"}},save:async next=>{saved=structuredClone(next)},store,now:()=>2000000000};
  const service=new Workspaces(options);
  const sign=async(op,fields={},who=wallet)=>{
    const body={action:"workspace-"+op,workspaceId,issuedAt:2000000000,wallet:who.address,nonce:crypto.randomUUID().replaceAll("-",""),...fields};
    return {...body,sig:await who.signMessage(canonical(body))};
  };
  const guest=async(op,fields={})=>{
    const body={action:"workspace-"+op,workspaceId,issuedAt:2000000000,sessionId:"stay",node_peer:peer,...fields};
    return {...body,sig:hex(await crypto.subtle.sign("Ed25519",receipt.privateKey,new TextEncoder().encode(canonical(body))))};
  };
  const candidate=async(version=1,previousHash=zero)=>{const data=new TextEncoder().encode("sealed workspace bytes ".repeat(4)+version);
    return {data,head:{version,previousHash,hash:await digest(data),size:data.length}}};
  return {service,sign,guest,candidate,wallet,other,session,broker,calls,store,options,
    restart:()=>new Workspaces({...options,state:saved})};
}
async function upload(f, candidate, guest=false) {
  const signed=guest?f.guest:f.sign;
  const started=await f.service.call("begin",await signed("begin",candidate.head));
  await f.service.call("chunk",await signed("chunk",{uploadId:started.uploadId,offset:0,data:b64(candidate.data)}));
  return {started,...await f.service.call("commit",await signed("commit",{uploadId:started.uploadId}))};
}

test("wallet/attested guest share one workspace chain; cross-owner signatures and conversations are refused",async()=>{
  const f=await fixture(),candidate=await f.candidate();
  const saved=await upload(f,candidate,true);
  assert.equal(saved.head.mac,mac,"Mac comes from the authenticated guest stay");
  assert.equal((await f.service.call("head",await f.sign("head"))).head.hash,candidate.head.hash);
  assert.equal((await f.service.call("head",await f.sign("head",{},f.other))).head,null);
  await assert.rejects(f.service.call("head",await f.guest("head",{workspaceId:"other-conversation"})),e=>e.code==="WORKSPACE_GUEST");
  f.session.final=true;
  await assert.rejects(f.service.call("head",await f.guest("head")),e=>e.code==="WORKSPACE_GUEST");
  const bad=await f.sign("head");bad.sig=(await f.sign("head",{},f.other)).sig;
  await assert.rejects(f.service.call("head",bad),e=>e.code==="WORKSPACE_SIGNATURE");
});

test("numbered commits reject stale parents and forks while idempotent retries and history survive restart",async()=>{
  const f=await fixture(),one=await upload(f,await f.candidate());
  const again=await f.service.call("begin",await f.sign("begin",{version:1,previousHash:zero,hash:one.head.hash,size:one.head.size}));
  assert.equal(again.committed,true);assert.equal(again.head.hash,one.head.hash);
  const two=await upload(f,await f.candidate(2,one.head.hash));
  await assert.rejects(f.service.call("begin",await f.sign("begin",(await f.candidate(2,zero)).head)),e=>e.code==="WORKSPACE_CONFLICT");
  const restarted=f.restart();
  assert.deepEqual((await restarted.call("history",await f.sign("history",{afterVersion:0}))).heads.map(h=>h.version),[1,2]);
  assert.equal((await restarted.call("head",await f.sign("head"))).head.hash,two.head.hash);
  assert.equal(await restarted.snapshotOwner({workspaceId,version:2,hash:two.head.hash}),mac);
  assert.equal(await restarted.snapshotOwner({workspaceId,version:1,hash:one.head.hash}),undefined);
  const read=await restarted.call("read",await f.sign("read",{version:2,hash:two.head.hash,offset:0}));
  assert.equal(read.nextOffset,two.head.size);assert.equal(read.source,"mac");assert.equal(read.ipfsFetched,false);
});

test("pending ciphertext upload resumes and recovers a Mac commit whose broker response was lost",async()=>{
  const f=await fixture(),candidate=await f.candidate();
  const begin=await f.service.call("begin",await f.sign("begin",candidate.head));
  await f.service.call("chunk",await f.sign("chunk",{uploadId:begin.uploadId,offset:0,data:b64(candidate.data)}));
  const restarted=f.restart();
  const resumed=await restarted.call("begin",await f.sign("begin",candidate.head));
  assert.equal(resumed.uploadId,begin.uploadId);assert.equal(resumed.offset,candidate.data.length);
  await f.store(mac,"commit",{uploadId:begin.uploadId});
  const recovered=await restarted.call("begin",await f.sign("begin",candidate.head));
  assert.equal(recovered.committed,true);
  assert.equal((await restarted.call("head",await f.sign("head"))).head.version,1);
});

test("snapshot declaration and chunks stay bounded before any storage write",async()=>{
  const f=await fixture(),candidate=await f.candidate();
  await assert.rejects(f.service.call("begin",await f.sign("begin",{...candidate.head,size:maxEncryptedSnapshotBytes+1})),e=>e.code==="WORKSPACE_REQUEST");
  assert.equal(f.calls.length,0);
  const begin=await f.service.call("begin",await f.sign("begin",candidate.head));
  await assert.rejects(f.service.call("chunk",await f.sign("chunk",{uploadId:begin.uploadId,offset:0,data:"A".repeat(4*Math.ceil(workspaceChunkBytes/3)+4)})),e=>e.code==="WORKSPACE_REQUEST");
  assert.equal(f.calls.length,1);
});

test("broker-to-Mac calls use the payment signer and recursively canonical EIP-191 envelope",async()=>{
  const f=await fixture();let seen;
  const server=Deno.serve({hostname:"127.0.0.1",port:0,onListen(){}},async request=>{
    seen=await request.json();const {sig,...unsigned}=seen;
    assert.equal(verifyMessage("dsmack-workspace-store/1\n"+canonicalFleet(unsigned),sig).toLowerCase(),f.broker.payments.key.address.toLowerCase());
    return Response.json({offset:0});
  });
  try {
    const service=new Workspaces({...f.options,cfg:{stores:{[mac]:"http://127.0.0.1:"+server.addr.port}},store:undefined});
    await service.remote(mac,"begin",{wallet:f.wallet.address.toLowerCase(),head:{workspaceId,version:1,hash:"ab".repeat(32)}});
    assert.equal(seen.action,"begin");assert.equal(seen.head.workspaceId,workspaceId);
  } finally {await server.shutdown();}
});
