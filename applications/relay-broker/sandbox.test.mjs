import { test } from "node:test";
import assert from "node:assert/strict";
import { sandbox, cors } from "./sandbox.mjs";
import { canonical } from "./grants.mjs";
import { hex, sha256 } from "../../dstack-compat/secret-release/policy.mjs";
const peer="node", target="/ip4/192.0.2.1/tcp/4001/p2p/relay/p2p-circuit/p2p/node";
const broker={cfg:{sandbox_forwarder:"http://127.0.0.1:18271"},live:()=>[{kind:"compute",relay_peer:peer,relay_maddr:target}]};
const readBody=req=>req.json();
const job={node_peer:peer,job_id:"aa".repeat(16),grant:{purchaseId:"bb".repeat(32)},sealed:{epk:"01".repeat(64),iv:"02".repeat(12),ct:"03".repeat(40)},client_peer:"buyer",signature:"04".repeat(64)};
const request=body=>new Request("http://broker/sandbox/jobs",{method:"POST",body:JSON.stringify(body)});

test("broker forwards only ciphertext to registered node with signed hash binding",async()=>{
 let forwarded;
 const result={status:"complete",outputs:{patch:{ct:"encrypted"}},statement:{job_id:job.job_id}};
 const response=await sandbox(request(job),broker,readBody,"token",async(url,init)=>{
  assert.equal(url,"http://127.0.0.1:18271/jobs");assert.equal(init.headers.authorization,"Bearer token");forwarded=JSON.parse(init.body);
  return Response.json(result);
 });
 assert.equal(response.status,200);assert.deepEqual(await response.json(),result);
 assert.equal(forwarded.target,target);assert.deepEqual(forwarded.sealed,job.sealed);
 assert.equal(forwarded.admission.bundle_sha256,hex(await sha256(new TextEncoder().encode(canonical(job.sealed)))));
 assert.equal(forwarded.admission.signature,job.signature);
 assert.deepEqual(Object.keys(forwarded).sort(),["admission","sealed","target"]);
});

test("unregistered destination cannot turn broker into an arbitrary libp2p dialer",async()=>{
 await assert.rejects(sandbox(request({...job,node_peer:"unregistered"}),broker,readBody,"",()=>assert.fail("must not dial")),/node_not_live/);
});

test("fresh paid challenge reaches live node and cannot be omitted",async()=>{
 const paid={...broker,live:()=>[{...broker.live()[0],payments:{}}]};
 await assert.rejects(sandbox(new Request("http://broker/sandbox/nodes/node/attestation"),paid,readBody,""),/fresh_challenge_required/);
 const challenge="ab".repeat(32);
 await sandbox(new Request("http://broker/sandbox/nodes/node/attestation?challenge="+challenge),paid,readBody,"",async(url,init)=>{
  assert.equal(url,"http://127.0.0.1:18271/attestation");assert.equal(JSON.parse(init.body).challenge,challenge);return Response.json({attestation:"proof"});
 });
});

test("node refusal is surfaced; lost result is not resubmitted",async()=>{
 const busy=await sandbox(request(job),broker,readBody,"",async()=>Response.json({status:"refused",error:"busy"}));assert.equal(busy.status,409);
 let calls=0;
 await assert.rejects(sandbox(request(job),broker,readBody,"",async()=>{calls++;throw Error("network");}),/node_result_lost/);
 assert.equal(calls,1);
});

test("CORS exposes only configured browser origins",()=>{
 const allowed=cors(new Request("http://broker",{headers:{origin:"http://app"}}),new Response(),["http://app"]);
 assert.equal(allowed.headers.get("access-control-allow-origin"),"http://app");
 assert.equal(cors(new Request("http://broker",{headers:{origin:"http://other"}}),new Response(),["http://app"]).headers.get("access-control-allow-origin"),null);
});
