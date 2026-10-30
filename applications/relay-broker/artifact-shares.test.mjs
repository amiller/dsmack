import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wallet, verifyMessage } from '../payments/schema.mjs';
import { canonical } from './grants.mjs';
import { canonicalFleet } from './fleet.mjs';
import { Continuity, cidFor } from './continuity.mjs';
import { ArtifactShares, artifactStoreRemote, maxArtifactCiphertextBytes } from './artifact-shares.mjs';
const encode = bytes => btoa(Array.from(bytes, c => String.fromCharCode(c)).join('')).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
function fixture() {
 const wallet = Wallet.createRandom(), records = new Map();let confirmed = true;
 const continuity = new Continuity({cfg:{}});
 const shares = new ArtifactShares({continuity,remote:async(action,body)=>{
  if(action==='raw-put'){records.set(body.cid,body.ciphertext);return {cid:body.cid,pinned:confirmed};}
  if(!records.has(body.cid))throw Object.assign(new Error('not published'),{status:404});
  return {cid:body.cid,ciphertext:records.get(body.cid)};
 }});
 const request = async(ciphertext,who=wallet)=>{
  const r={action:'artifact-share',wallet:who.address,nonce:crypto.randomUUID().replaceAll('-',''),issuedAt:Math.floor(Date.now()/1000),ciphertext};return {...r,sig:await who.signMessage(canonical(r))};
 };
 return {wallet,shares,records,request,unconfirm:()=>{confirmed=false;}};
}
test('publishes signed ciphertext only after pin confirmation and reads the exact content-addressed bytes publicly',async()=>{
 const f=fixture(), bytes=crypto.getRandomValues(new Uint8Array(80)),ciphertext=encode(bytes),request=await f.request(ciphertext);
 const result=await f.shares.publish(request);assert.deepEqual(result,{cid:await cidFor(bytes),pinned:true});
 assert.deepEqual(await f.shares.read(result.cid),{cid:result.cid,ciphertext});
 await assert.rejects(f.shares.publish(request),/replayed/);
 f.records.set(result.cid,encode(new Uint8Array(80)));await assert.rejects(f.shares.read(result.cid),/CID mismatch/);
 f.unconfirm();await assert.rejects(f.shares.publish(await f.request(ciphertext)),/not confirmed/);
});
test('refuses forged owners, oversize uploads and non-published reads',async()=>{
 const f=fixture(),r=await f.request(encode(new Uint8Array(40)));r.wallet=Wallet.createRandom().address;
 await assert.rejects(f.shares.publish(r),/signature/);
 await assert.rejects(f.shares.publish(await f.request(encode(new Uint8Array(maxArtifactCiphertextBytes+1)))),/512 KiB/);
 await assert.rejects(f.shares.read(await cidFor(new Uint8Array(50))),/not published/);
});
test('store transport signs the existing broker domain and bounds store responses',async()=>{
 const key=Wallet.createRandom();let sent;
 const remote=artifactStoreRemote({url:'https://store.example.invalid',key,fetch:async(url,options)=>{
  sent=JSON.parse(options.body);assert.equal(url,'https://store.example.invalid/raw-get');
  const {sig,...unsigned}=sent;assert.equal(verifyMessage('dsmack-workspace-store/1\n'+canonicalFleet(unsigned),sig),key.address);
  return Response.json({cid:sent.cid,ciphertext:'test'});
 }});
 assert.deepEqual(await remote('raw-get',{wallet:'0x'+'0'.repeat(40),cid:'test'}),{cid:'test',ciphertext:'test'});
 const excessive=artifactStoreRemote({url:'https://store.example.invalid',key,fetch:async()=>new Response(new Uint8Array(1024*1024+1))});
 await assert.rejects(excessive('raw-get',{}),/exceeds 1 MiB/);
});
