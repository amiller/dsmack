import { test } from "node:test";
import assert from "node:assert/strict";
import { sandbox } from "./sandbox.mjs";
const peer="node", target="/ip4/192.0.2.1/tcp/4001/p2p/relay/p2p-circuit/p2p/node";
const broker={cfg:{},live:()=>[{kind:"compute",relay_peer:peer,relay_maddr:target}]};
const request=(node=peer)=>new Request("http://broker/sandbox/nodes/"+node+"/attestation");
const transport=forward=>async()=>({forward});

test("unregistered destination cannot turn broker into an arbitrary libp2p dialer",async()=>{
 await assert.rejects(sandbox(request("unregistered"),broker,transport(()=>assert.fail("must not dial"))),/node_not_live/);
});

test("fresh paid challenge reaches live node and cannot be omitted",async()=>{
 const paid={...broker,live:()=>[{...broker.live()[0],payments:{}}]};
 await assert.rejects(sandbox(new Request("http://broker/sandbox/nodes/node/attestation"),paid),/fresh_challenge_required/);
 const challenge="ab".repeat(32);
 await sandbox(new Request("http://broker/sandbox/nodes/node/attestation?challenge="+challenge),paid,transport(async(endpoint,payload)=>{
  assert.equal(endpoint,"attestation");assert.equal(payload.challenge,challenge);return {attestation:"proof"};
 }));
});

test('free diagnostic discovery uses the free attestation protocol despite a browser nonce',async()=>{
 let forwarded;const response=await sandbox(new Request('https://broker/sandbox/nodes/node/attestation?challenge='+ 'ab'.repeat(32)),broker,transport(async(_endpoint,payload)=>{forwarded=payload;return {attestation:'proof'}}));
 assert.equal(response.status,200);assert.equal(forwarded.challenge,'');
});

test("network 502 preserves the nested dial cause and stage", async () => {
 const detail={name:"AggregateError",message:"All multiaddr dials failed",errors:[
  {name:"Error",message:"hop refused",cause:{name:"Error",message:"reservation expired"}},
 ]};
 const error=Object.assign(new Error("node_unreachable"),{code:"node_unreachable",stage:"node_unreachable",status:502,detail});
 const response=await sandbox(request(),broker,transport(async()=>{throw error}));
 assert.equal(response.status,502);
 assert.deepEqual(await response.json(),{error:"node_unreachable",stage:"node_unreachable",detail});
});
