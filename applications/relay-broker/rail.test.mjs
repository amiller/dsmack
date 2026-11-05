import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { Payments, LEASE_KIND, deepCanonical } from "./payments.mjs";
import { Claim, claimDomain, Wallet, verifyTypedData } from "../payments/schema.mjs";
const escrow="0x1000000000000000000000000000000000000001";

test("finalized lifetime deposits credit once across concurrent refresh and restart; exits persist",async()=>{
 const wallet=Wallet.createRandom().address.toLowerCase();
 let deposited=1000000n,exit=0n,saved;
 const options={cfg:{escrow},key:Wallet.createRandom(),save:async s=>{saved=structuredClone(s)},
  quorum:{snapshot:async()=>({call:async name=>name==="deposits"?deposited:exit})}};
 let p=new Payments(options);
 await Promise.all([p.syncBalance(wallet),p.syncBalance(wallet)]);
 assert.equal(p.state.inferenceCredit[wallet].grantedNanoUsd,"1000000000");
 p=new Payments({...options,state:saved});deposited+=100n;exit=2000000000n;
 await p.syncBalance(wallet);
 assert.equal(p.state.inferenceCredit[wallet].grantedNanoUsd,"1000100000");
 assert.equal(p.state.inferenceCredit[wallet].exitRequestedAt,2000000000);
 exit=0n;await assert.rejects(p.syncBalance(wallet),/exit counter regressed/);exit=2000000000n;
 p.save=async()=>{throw Error("disk full")};deposited+=10n;
 await assert.rejects(p.syncBalance(wallet),/disk full/);
 assert.equal(p.state.inferenceCredit[wallet].depositedNanoUsd,"1000100000");
});

test("lease statements accrue once under accepted terms, within the cap, and sign the terms claim",async()=>{
 const user=Wallet.createRandom().address,operator=Wallet.createRandom().address.toLowerCase(),terms="0x"+"ab".repeat(32);
 const statement=(lease_id,owed,extra={})=>({kind:LEASE_KIND,lease_id,buyer_wallet:user,operator,terms_hash:terms,owed,chain_id:84532,escrow,...extra});
 let onChain={operator,cap:5000000n};
 const p=new Payments({cfg:{escrow},key:Wallet.createRandom(),save:async()=>{},now:()=>31*604800,
  quorum:{snapshot:async()=>({call:async(name,args)=>{assert.equal(name,"terms");assert.deepEqual(args,[user,terms]);return onChain;}})}});
 p.verifyLease=async st=>deepCanonical(st);
 await assert.rejects(p.termsClaim(user,terms),/no accrued usage/);
 assert.deepEqual(await p.leaseStatement({statement:statement("l1","2000000")},{}),{operator,owed:"2000000"});
 assert.deepEqual(await p.leaseStatement({statement:statement("l1","2000000")},{}),{operator,owed:"2000000"});
 await assert.rejects(p.leaseStatement({statement:statement("l1","2000001")},{}),/different statement/);
 await assert.rejects(p.leaseStatement({statement:statement("l2","3000001")},{}),/terms cap/);
 assert.deepEqual(await p.leaseStatement({statement:statement("l2","3000000")},{}),{operator,owed:"5000000"});
 await assert.rejects(p.leaseStatement({statement:statement("l3","1",{operator:user})},{}),/terms not accepted/);
 await assert.rejects(p.leaseStatement({statement:statement("l3","1",{escrow:user})},{}),/statement escrow/);
 await assert.rejects(p.leaseStatement({statement:{...statement("l3","1"),terms_hash:undefined}},{}),/terms_hash/);
 const signed=await p.termsClaim(user,terms);
 assert.deepEqual(signed.claim,{operator,termsHash:terms,cumulativeOwed:"5000000",period:31});
 assert.equal(verifyTypedData(claimDomain(escrow,user.toLowerCase()),{Claim},signed.claim,signed.signature),p.key.address);
});

test("lease attestation must be an admitted guest's and cover this exact statement",async()=>{
 const f=JSON.parse(readFileSync(new URL("fixtures/bind.json",import.meta.url)));
 const p=new Payments({cfg:{escrow},key:Wallet.createRandom(),save:async()=>{},quorum:{}});
 const st={kind:LEASE_KIND,lease_id:"l1"};
 await assert.rejects(p.verifyLease(st,f.paid.attestation,{leaseWorkloads:[]},{}),/lease guest workload is not admitted/);
 const workload={manifest_sha256:f.paid.manifest_sha256,os_image_hash:f.paid.os_image_hash,cdhash:f.paid.cdhash};
 await assert.rejects(p.verifyLease(st,f.paid.attestation,{leaseWorkloads:[{...workload,service:"guest"}]},{}),/caller is not the lease service/);
 await assert.rejects(p.verifyLease(st,f.paid.attestation,{leaseWorkloads:[{...workload,service:"node"}]},{}),/does not cover this statement/);
 assert.equal(deepCanonical({b:[{d:1,c:"x"}],a:{z:null,y:true}}),'{"a":{"y":true,"z":null},"b":[{"c":"x","d":1}]}');
 assert.throws(()=>deepCanonical({a:1.5}),/integers/);
});
