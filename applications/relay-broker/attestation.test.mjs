import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Wallet } from "../payments/schema.mjs";
import { unhex } from "../../dstack-compat/secret-release/policy.mjs";
import { verifyRelay, withEnrollment } from "./attestation.mjs";
const f=JSON.parse(readFileSync(new URL("fixtures/bind.json",import.meta.url)));
const chain=()=>withEnrollment({category:async()=>3,rpIdHash:async()=>unhex(f.rp_id_hash),buildId:async()=>new Uint8Array(32),burnedBuild:async()=>false,burnedImage:async()=>false},[f.enrollment]);
test("paid registration binds its settlement key and fresh challenge",async()=>{
 const r=f.paid,cfg={workloads:[{...r,service:"node"}]},now=1793120000;
 await verifyRelay(r,cfg,chain(),now);
 await assert.rejects(verifyRelay({...r,payments:{...r.payments,receiptSigner:Wallet.createRandom().address}},cfg,chain(),now),/paid receipt public key\/signer/);
 await assert.rejects(verifyRelay({...r,payments:{...r.payments,challenge:"01".repeat(32)}},cfg,chain(),now),/binding/);
});
test("the registry, not the workload config or the manifest's CDHash, decides the copy that signed",async()=>{
 const r=f.paid,now=1793120000,{cdhash,...w}=r,cfg={workloads:[{...w,service:"node"}]};
 assert.equal((await verifyRelay({...r,cdhash:"ab".repeat(32)},cfg,chain(),now)).cdhash,cdhash);
 await assert.rejects(verifyRelay(r,cfg,{...chain(),rpIdHash:async()=>new Uint8Array(32)},now),/approved CDRegistry build/);
});
