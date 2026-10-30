import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EmailGate} from './email-gate.mjs';
import {random,ephemeral,seal,open} from './email-gate-crypto.mjs';
const bundle={v:1,dk:random(),walletKey:'0x'+'42'.repeat(32)};
async function fixture(){let state;const sent=[];const gate=await new EmailGate({load:async()=>state,save:async(s)=>{state=structuredClone(s);},sendEmail:async(message)=>sent.push(message),quote:async()=>({})}).initialize();return {gate,sent,state:()=>state};}
const post=async(gate,path,body)=>{const response=await gate.handle(new Request('https://private-agent.example/continuity/email/'+path,{method:'POST',body:JSON.stringify(body)}));return {status:response.status,...await response.json()};};
async function request(gate,pair,purpose,email='test@example.com'){return post(gate,'request',{email,publicKey:pair.publicKey,purpose});}
async function enroll(f,pair,email){const context=await request(f.gate,pair,'enroll',email);const sealed=await seal(pair.privateKey,f.gate.state.publicKey,bundle,'dsmack-email-enroll/1|'+context.id);return post(f.gate,'confirm',{id:context.id,code:f.sent.at(-1).code,sealed});}
test('email recovery seals keys to requesting device and consumes its code',async()=>{
 const f=await fixture(),a=await ephemeral(),b=await ephemeral();
 assert.equal((await enroll(f,a)).status,200);
 assert.ok(!JSON.stringify(f.state().accounts).includes(bundle.walletKey));
 const context=await request(f.gate,b,'recover');
 const recovered=await post(f.gate,'confirm',{id:context.id,code:f.sent.at(-1).code});
 assert.equal(recovered.status,200);
 assert.deepEqual(await open(b.privateKey,f.gate.state.publicKey,recovered.sealed,'dsmack-email-recover/1|'+context.id),bundle);
 await assert.rejects(open(a.privateKey,f.gate.state.publicKey,recovered.sealed,'dsmack-email-recover/1|'+context.id));
 assert.equal((await post(f.gate,'confirm',{id:context.id,code:f.sent.at(-1).code})).status,403);
});
test('five incorrect guesses lock the challenge and email throttles repeated sends',async()=>{
 const f=await fixture(),a=await ephemeral(),context=await request(f.gate,a,'recover');
 const wrong=f.sent[0].code==='000000'?'000001':'000000';
 for(let n=0;n<5;n++)assert.equal((await post(f.gate,'confirm',{id:context.id,code:wrong})).status,403);
 assert.equal((await post(f.gate,'confirm',{id:context.id,code:f.sent[0].code})).status,429);
 await request(f.gate,a,'recover');await request(f.gate,a,'recover');
 assert.equal((await request(f.gate,a,'recover')).status,429);
});
test('email enrollment cannot overwrite the existing recovery bundle',async()=>{
 const f=await fixture(),a=await ephemeral();assert.equal((await enroll(f,a)).status,200);assert.equal((await enroll(f,a)).status,409);
});
