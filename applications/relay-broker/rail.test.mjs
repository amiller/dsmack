import assert from "node:assert/strict";
import { test } from "node:test";
import { Payments, accrue } from "./payments.mjs";
import { Claim, claimDomain, Wallet, verifyTypedData } from "../payments/schema.mjs";
const escrow="0x1000000000000000000000000000000000000001";

test("finalized lifetime deposits credit once across concurrent refresh and restart; exits persist",async()=>{
 const wallet=Wallet.createRandom().address.toLowerCase();
 let deposited=1000000n,exit=0n,saved;
 const options={cfg:{escrow},key:Wallet.createRandom(),save:async s=>{saved=structuredClone(s)},
  chain:{snapshot:async()=>({call:async name=>name==="deposits"?deposited:exit})}};
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

test("weekly cumulative claims isolate user/operator funds, retain rounding dust, and exclude gifts",async()=>{
 const user=Wallet.createRandom().address.toLowerCase(),other=Wallet.createRandom().address.toLowerCase();
 const operator=Wallet.createRandom().address.toLowerCase(),second=Wallet.createRandom().address.toLowerCase();
 let now=30*604800;
 const p=new Payments({cfg:{escrow},key:Wallet.createRandom(),chain:{},save:async()=>{},now:()=>now,
  state:{inferenceCredit:{[user]:{depositedNanoUsd:"5000"},[other]:{depositedNanoUsd:"0"}}}});
 const debit=(wallet,payee,charge)=>{
  const allocation=accrue(p.state,wallet,payee,BigInt(charge),now);
  if(allocation.prepaidSpentNanoUsd)p.state.inferenceCredit[wallet].prepaidSpentNanoUsd=allocation.prepaidSpentNanoUsd;
  if(allocation.operatorAccruals)p.state.operatorAccruals=allocation.operatorAccruals;
 };
 debit(user,operator,1999);debit(user,second,1000);debit(other,operator,2000);
 await assert.rejects(p.weeklyClaim(user,operator,30),/completed week/);
 now+=604800;
 const first=await p.weeklyClaim(user,operator,30);
 assert.equal(first.claim.cumulativeOwed,"1");
 assert.equal(verifyTypedData(claimDomain(escrow,user),{Claim},first.claim,first.signature),p.key.address);
 assert.notEqual(verifyTypedData(claimDomain(escrow,other),{Claim},first.claim,first.signature),p.key.address);
 debit(user,operator,5000); // Only the remaining 2001 deposited nano-USD can fund claims.
 now+=604800;
 assert.equal((await p.weeklyClaim(user,operator,31)).claim.cumulativeOwed,"4");
 assert.equal((await p.weeklyClaim(user,second,31)).claim.cumulativeOwed,"1");
 await assert.rejects(p.weeklyClaim(other,operator,31),/no funded usage/);
 assert.equal(p.state.inferenceCredit[user].prepaidSpentNanoUsd,"5000");
});
