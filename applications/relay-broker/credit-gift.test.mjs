import assert from "node:assert/strict";
import { test } from "node:test";
import { Wallet } from "../payments/schema.mjs";
import { Payments } from "./payments.mjs";
import { Inference, creditGrantPrefix } from "./inference.mjs";
import { canonical } from "./grants.mjs";
import { grantCredit } from "../payments/grant-credit.mjs";

async function fixture() {
  let now = Math.floor(Date.now()/1000), saved;
  const wallet=Wallet.createRandom(),issuer=Wallet.createRandom(),other=Wallet.createRandom();
  const escrow="0x"+"81".repeat(20),brokerKey="17".repeat(32);
  const payments=new Payments({cfg:{},key:{},quorum:{},save:async next=>{saved=structuredClone(next)}});
  const inference=new Inference({payments,cfg:{model:"fixture",starterCreditNanoUsd:"200000"},now:()=>now});
  const request={action:"credit",wallet:wallet.address,nonce:"ab".repeat(16),issuedAt:now};
  await inference.credit({...request,sig:await wallet.signMessage(canonical(request))});
  const domain={issuer:issuer.address,escrow,brokerKey};
  const voucher=async(fields={},signer=issuer)=>{
    const grant={v:1,chainId:84532,escrow,brokerKey,wallet:wallet.address,amountNanoUsd:"300000",
      nonce:crypto.randomUUID().replaceAll("-","")+crypto.randomUUID().replaceAll("-",""),expiresAt:now+600,...fields};
    return {grant,signature:await signer.signMessage(creditGrantPrefix+canonical(grant))};
  };
  return {wallet,issuer,other,escrow,brokerKey,payments,inference,domain,voucher,
    saved:()=>saved,advance:seconds=>now+=seconds};
}

test("only the configured funding wallet adds domain-bound gift credit once across restarts",async()=>{
 const f=await fixture(),gift=await f.voucher(),wallet=f.wallet.address.toLowerCase();
 await assert.rejects(f.inference.grantCredit(await f.voucher({},f.other),f.domain),e=>e.code==="CREDIT_GIFT_SIGNATURE");
 await assert.rejects(f.inference.grantCredit(await f.voucher({brokerKey:"18".repeat(32)}),f.domain),e=>e.code==="CREDIT_GIFT_REQUEST");
 await assert.rejects(f.inference.grantCredit(await f.voucher({escrow:"0x"+"82".repeat(20)}),f.domain),e=>e.code==="CREDIT_GIFT_REQUEST");
 const simultaneous=await Promise.all([f.inference.grantCredit(gift,f.domain),f.inference.grantCredit(gift,f.domain)]);
 assert.equal(simultaneous.filter(receipt=>receipt.applied).length,1);
 assert.equal(f.inference.summary(wallet).grantedNanoUsd,"500000");
 const restarted=new Inference({payments:new Payments({cfg:{},key:{},quorum:{},state:f.saved(),save:async()=>{throw Error("duplicate gift must not write")}}),
  cfg:{model:"fixture"},now:()=>gift.grant.expiresAt+1});
 assert.equal((await restarted.grantCredit(gift,f.domain)).applied,false);
 assert.equal(restarted.summary(wallet).grantedNanoUsd,"500000");
 await assert.rejects(f.inference.grantCredit(await f.voucher({nonce:gift.grant.nonce,amountNanoUsd:"400000"}),f.domain),e=>e.code==="CREDIT_GIFT_REPLAY");
});

test("gift authorization expires and failed persistence cannot consume a nonce or increase credit",async()=>{
 const f=await fixture(),gift=await f.voucher(),wallet=f.wallet.address.toLowerCase();
 const save=f.payments.save;f.payments.save=async()=>{throw Error("disk full")};
 await assert.rejects(f.inference.grantCredit(gift,f.domain),/disk full/);
 assert.equal(f.inference.summary(wallet).grantedNanoUsd,"200000");
 assert.equal(f.payments.state.inferenceGifts,undefined);
 f.payments.save=save;
 assert.equal((await f.inference.grantCredit(gift,f.domain)).applied,true);
 f.advance(601);
 await assert.rejects(f.inference.grantCredit(await f.voucher({expiresAt:gift.grant.expiresAt}),f.domain),e=>e.code==="CREDIT_GIFT_REQUEST");
});

test("gift CLI requires the configured broker pin and retries its saved authorization without minting twice",async()=>{
 const f=await fixture(),dir=await Deno.makeTempDir();
 const server=Deno.serve({hostname:"127.0.0.1",port:0,onListen(){}},async request=>{
  const path=new URL(request.url).pathname;
  if(path==="/key")return Response.json({public_key:f.brokerKey});
  if(path==="/payments/key")return Response.json({chainId:84532,address:f.other.address,escrow:f.escrow,codeHash:"fixture-code"});
  if(path==="/inference/grant-credit")return Response.json(await f.inference.grantCredit(await request.json(),f.domain));
  return new Response(null,{status:404});
 });
 try {
  const url="http://127.0.0.1:"+server.addr.port,config=dir+"/config.json",key=dir+"/funding.key",out=dir+"/gift.json";
  const cfg={brokerKey:f.brokerKey,payments:{fundingAddress:f.issuer.address,escrow:f.escrow,grantSigner:f.other.address,codeHash:"fixture-code"}};
  await Deno.writeTextFile(config,JSON.stringify({...cfg,brokerKey:"18".repeat(32)}));
  await assert.rejects(grantCredit([config,key,url,f.wallet.address,"300000",out,"--send"]),/broker differs/);
  await Deno.writeTextFile(config,JSON.stringify(cfg));await Deno.writeTextFile(key,f.issuer.privateKey,{mode:0o600});
  await grantCredit([config,key,url,f.wallet.address,"300000",out,"--send"]);
  const original=await Deno.readTextFile(out);
  await grantCredit([config,key,url,f.wallet.address,"300000",out,"--send"]);
  assert.equal(await Deno.readTextFile(out),original);
  assert.equal(f.inference.summary(f.wallet.address.toLowerCase()).grantedNanoUsd,"500000");
  assert.equal(Object.keys(f.payments.state.inferenceGifts).length,1);
 } finally {await server.shutdown();await Deno.remove(dir,{recursive:true});}
});
