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


const emptyAttestation = () => Object.assign(new Error("node_attestation", {
 cause: Object.assign(new Error("guest closed without an attestation response"), {code:"EMPTY_ATTESTATION_RESPONSE"}),
}), {code:"node_attestation",stage:"node_attestation",status:502,
 detail:{name:"EmptyAttestationResponseError",message:"guest closed without an attestation response"}});

test("one empty attestation retries the same peer and challenge within one operation signal",async()=>{
 const paid={...broker,live:()=>[{...broker.live()[0],payments:{}}]}, challenge="ab".repeat(32), calls=[];
 const response=await sandbox(new Request("https://broker/sandbox/nodes/node/attestation?challenge="+challenge),paid,
  transport(async(endpoint,payload,options)=>{
   calls.push({endpoint,payload,signal:options.signal});
   if(calls.length===1)throw emptyAttestation();
   return {attestation:"fresh-proof",challenge};
  }));
 assert.equal(response.status,200);
 assert.deepEqual(await response.json(),{attestation:"fresh-proof",challenge});
 assert.equal(calls.length,2);
 assert.strictEqual(calls[0].payload,calls[1].payload);
 assert.equal(calls[1].payload.target,target);
 assert.equal(calls[1].payload.challenge,challenge);
 assert.strictEqual(calls[0].signal,calls[1].signal);
});

test("repeated empty attestations stop after the second read",async()=>{
 let calls=0;
 const response=await sandbox(request(),broker,transport(async()=>{calls++;throw emptyAttestation();}));
 assert.equal(response.status,502);
 assert.equal(calls,2);
 assert.equal((await response.json()).detail.name,"EmptyAttestationResponseError");
});

test("nonempty invalid JSON, cryptographic refusal and other network errors are not retried",async()=>{
 for(const cause of [new SyntaxError("invalid attestation JSON"),new Error("signature refused"),new Error("connection reset")]){
  let calls=0;
  const error=Object.assign(new Error("node_attestation",{cause}),{stage:"node_attestation",code:"node_attestation",
   status:502,detail:{name:cause.name,message:cause.message}});
  const response=await sandbox(request(),broker,transport(async()=>{calls++;throw error;}));
  assert.equal(response.status,502);
  assert.equal(calls,1);
 }
});

test("an aborted request cannot retry an empty attestation",async()=>{
 const controller=new AbortController();let calls=0;
 const req=new Request("https://broker/sandbox/nodes/node/attestation",{signal:controller.signal});
 const response=await sandbox(req,broker,transport(async()=>{calls++;controller.abort();throw emptyAttestation();}));
 assert.equal(response.status,502);
 assert.equal(calls,1);
});
