import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,sign} from 'node:crypto';
import {parseHeaders,canonicalHeader,signatureInput,verifyHeaderSignature,verifyDkimRecovery,fetchDkimKey,rsaKey} from './dkim-verifier.mjs';
import {ephemeral,emailRecoveryNonce,emailRecoveryLabel,seal,open,random} from './email-gate-crypto.mjs';
import {EmailGate} from './email-gate.mjs';
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const record='v=DKIM1; k=rsa; p='+publicKey.export({type:'spki',format:'der'}).toString('base64');
const now=Date.now();
async function message({pair,email='test@example.com',userId=email,ts=now,mode='relaxed',extra='',signed='from:subject:date',key=privateKey}={}) {
 pair??=await ephemeral();
 const nonce=await emailRecoveryNonce(pair.publicKey,userId,ts);
 const header=`DKIM-Signature: v=1; a=rsa-sha256; c=${mode}/relaxed; d=example.com; s=test; h=${signed}; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; ${extra}b=`;
 const fields=`From: Test Sender <${email}>\r\nSubject: dsmack-recover ${nonce}\r\nDate: ${new Date(ts).toUTCString()}`;
 const headers=parseHeaders(header+'\r\n'+fields);
 const b=sign('sha256',signatureInput(headers,headers[0]),key).toString('base64');
 return {pair,proof:{headers:header+b+'\r\n'+fields,email,userId,ts,publicKey:pair.publicKey,nonce}};
}
const verify=(proof,options={})=>verifyDkimRecovery(proof,{now,lookup:async()=>record,...options});
test('RFC6376 section3.4.5 simple and relaxed header vectors',()=>{
 const h=parseHeaders('A: X\r\nB : Y\t\r\n\t Z  ');
 assert.equal(h.map(x=>canonicalHeader(x,'relaxed')).join(''),'a:X\r\nb:Y Z\r\n');
 assert.equal(h.map(x=>canonicalHeader(x,'simple')).join(''),'A: X\r\nB : Y\t\r\n\t Z  \r\n');
});
test('RFC8463 Appendix A published RSA signature verifies including oversigned fields',async()=>{
 const raw=readFileSync(new URL('./test-fixtures/rfc8463-headers.txt',import.meta.url),'utf8');
 const key=readFileSync(new URL('./test-fixtures/rfc8463-key.txt',import.meta.url),'utf8').trim();
 const headers=parseHeaders(raw),signature=headers.find(h=>h.name==='dkim-signature'&&h.raw.includes('a=rsa-sha256'));
 assert.equal(await verifyHeaderSignature(headers,signature,key),true);
 assert.equal((await rsaKey(key)).algorithm.modulusLength,1024);
 // RFC fixture is intentionally too weak for recovery's 2048-bit policy.
});
test('locally signed RSA2048 relaxed and simple recovery headers verify',async()=>{
 for(const mode of ['simple','relaxed']){const {proof}=await message({mode});assert.equal((await verify(proof)).email,proof.email);}
 const pkcs1='v=DKIM1; k=rsa; p='+publicKey.export({type:'pkcs1',format:'der'}).toString('base64');
 assert.equal((await rsaKey(pkcs1)).algorithm.modulusLength,2048);
});
test('changed nonce/key, stale Date, unsigned Date, duplicate From, l= and weak keys cannot release keys',async()=>{
 const {proof}=await message();
 await assert.rejects(verify({...proof,publicKey:(await ephemeral()).publicKey}),/nonce/);
 await assert.rejects(verify({...proof,ts:now-31*60_000}),/expired/);
 await assert.rejects(verify({...proof,headers:proof.headers.replace('Subject: dsmack-recover','Subject: altered')}),/subject/);
 await assert.rejects(verify({...proof,headers:proof.headers.replace(/^Date:.*$/m,'Date: '+new Date(now-31*60_000).toUTCString())}),/expired/);
 await assert.rejects(verify({...proof,headers:proof.headers+'\r\nFrom: attacker@example.com'}),/one from/);
 await assert.rejects(verify((await message({signed:'from:subject'})).proof),/sign From, Subject and Date/);
 await assert.rejects(verify((await message({extra:'l=0; '})).proof),/body length/);
 const weak=generateKeyPairSync('rsa',{modulusLength:1024});
 await assert.rejects(verify((await message({key:weak.privateKey})).proof,{lookup:async()=>'v=DKIM1; p='+weak.publicKey.export({type:'spki',format:'der'}).toString('base64')}),/2048/);
 const altered={...proof,headers:proof.headers.replace('Test Sender','Another Sender')};
 await assert.rejects(verify(altered),/signature/);
 await assert.rejects(verify({...proof,headers:proof.headers.replace('d=example.com','d=attacker.example')}),/aligned/);
});
test('two DoH resolvers must agree, quoted TXT chunks and bare Google records normalize',async()=>{
 let calls=0;
 const fetch=async()=>new Response(JSON.stringify({Status:0,Answer:[{type:16,data:++calls===1?'"'+record.slice(0,100)+'" "'+record.slice(100)+'"':record}]}));
 assert.equal(await fetchDkimKey('test._domainkey.example.com',{fetch}),record);assert.equal(calls,2);
 calls=0;
 await assert.rejects(fetchDkimKey('test._domainkey.example.com',{fetch:async()=>new Response(JSON.stringify({Status:0,Answer:[{type:16,data:++calls===1?record:record.replace('k=rsa','k=ed25519')}]}))}),/disagree/);
});
test('gate enrolls labelled wrap and fresh browser recovers same bundle without replay state',async()=>{
 let state;const gate=await new EmailGate({load:async()=>state,save:async s=>{state=structuredClone(s);},now:()=>now,verifyDkim:(p,o)=>verifyDkimRecovery(p,{...o,lookup:async()=>record})}).initialize();
 const a=await message(),bundle={v:1,dk:random(),walletKey:'0x'+'42'.repeat(32)},label=emailRecoveryLabel(a.proof.email,a.proof.userId);
 const post=async body=>{const r=await gate.handle(new Request('https://test/continuity/email/dkim',{method:'POST',body:JSON.stringify(body)}));return {status:r.status,...await r.json()};};
 const sealed=await seal(a.pair.privateKey,gate.state.publicKey,bundle,label+'|enroll|'+a.proof.nonce);
 assert.equal((await post({...a.proof,purpose:'enroll',sealed})).status,200);
 assert.ok(!JSON.stringify(state).includes(bundle.walletKey));
 assert.equal((await post({...a.proof,purpose:'enroll',sealed})).status,409);
 const b=await message(),recovered=await post({...b.proof,purpose:'recover'});assert.equal(recovered.status,200);
 assert.deepEqual(await open(b.pair.privateKey,gate.state.publicKey,recovered.sealed,label+'|recover|'+b.proof.nonce),bundle);
 await assert.rejects(open(a.pair.privateKey,gate.state.publicKey,recovered.sealed,label+'|recover|'+b.proof.nonce));
 assert.equal((await post({...b.proof,purpose:'recover'})).status,200);
});
