import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet, domain, NodeBinding, nodeBindingSigner } from "../payments/schema.mjs";
import { Payments } from "./payments.mjs";

test("new run bindings cover the attested run expiry; an existing signed binding is never rewritten",async()=>{
 let now=2000000000;
 const key=Wallet.createRandom(),escrow="0x"+"81".repeat(20),runId="0x"+"ab".repeat(32),node="0x"+"cd".repeat(32);
 const registration={manifest_sha256:"12".repeat(32),os_image_hash:"34".repeat(32),payments:{node,runId,
  operator:Wallet.createRandom().address,receiptSigner:Wallet.createRandom().address,runExpires:now+3600}};
 let saved;
 const broker=new Payments({cfg:{escrow},key,quorum:{},now:()=>now,save:async state=>{saved=structuredClone(state)}});
 const first=await broker.bindRun(registration,{build_id:"approved"},"finalized-block");
 assert.equal(first.nodeBinding.binding.expires,registration.payments.runExpires);
 assert.equal(nodeBindingSigner(escrow,first.nodeBinding),key.address);
 now+=700;
 assert.deepEqual((await broker.bindRun(registration,{build_id:"approved"},"another-finalized-block")).nodeBinding,first.nodeBinding);
 const oldValue={...first.nodeBinding.binding,expires:now+600};
 const old={binding:oldValue,signature:await key.signTypedData(domain(escrow),{NodeBinding},oldValue)};
 const legacy=new Payments({cfg:{escrow},key,quorum:{},now:()=>now,state:{...saved,bindings:{[runId]:old}},
  save:async()=>{throw Error("existing binding must not be rewritten")}});
 assert.deepEqual((await legacy.bindRun(registration,{},"block")).nodeBinding,old);
 now+=601;
 await assert.rejects(legacy.bindRun(registration,{},"block"),/run binding changed or expired/);
});
