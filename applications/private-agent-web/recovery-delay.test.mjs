import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EmailGate} from './email-gate.mjs';
import {random,ephemeral,seal,open,recoveryControl,emailRecoveryLabel} from './email-gate-crypto.mjs';
const bundle={v:1,dk:random(),walletKey:'0x'+'42'.repeat(32)};
const delay=48*60*60_000,email='test@example.com',label=emailRecoveryLabel(email,email);
const post=async(gate,path,body)=>{const response=await gate.handle(new Request('https://private-agent.example/continuity/email/'+path,{method:'POST',body:JSON.stringify(body)}));return {status:response.status,...await response.json()};};
async function fixture(){
 let state,time=Date.now();
 const options={load:async()=>structuredClone(state),save:async s=>{state=structuredClone(s);},now:()=>time,verifyDkim:async p=>({nonce:p.nonce})};
 let gate=await new EmailGate(options).initialize();
 const pair=await ephemeral(),nonce=random(),proof={email,userId:email,publicKey:pair.publicKey,nonce};
 const sealed=await seal(pair.privateKey,gate.state.publicKey,bundle,label+'|enroll|'+nonce);
 assert.equal((await post(gate,'dkim',{...proof,purpose:'enroll',sealed})).status,200);
 return {get gate(){return gate;},time:()=>time,advance:n=>time+=n,state:()=>state,restart:async()=>{gate=await new EmailGate(options).initialize();}};
}
async function recover(){const pair=await ephemeral(),nonce=random();return {pair,proof:{email,userId:email,publicKey:pair.publicKey,nonce,purpose:'recover'}};}
test('DKIM recovery persists its 48-hour gate deadline and seals release only to the requesting device',async()=>{
 const f=await fixture(),a=await recover(),start=f.time();
 const pending=await post(f.gate,'dkim',a.proof);
 assert.equal(pending.status,202);assert.equal(pending.releaseAt,start+delay);assert.equal(pending.sealed,undefined);
 assert.ok(!JSON.stringify(f.state()).includes(bundle.walletKey));
 f.advance(60_000);
 assert.equal((await post(f.gate,'dkim',a.proof)).releaseAt,start+delay,'retries cannot reset the clock');
 assert.equal((await post(f.gate,'dkim',(await recover()).proof)).status,409);
 await f.restart();f.advance(delay-60_000-1);
 assert.equal((await post(f.gate,'release',{id:pending.id})).status,202);
 f.advance(1);
 const released=await post(f.gate,'release',{id:pending.id});
 assert.equal(released.status,200);
 assert.deepEqual(await open(a.pair.privateKey,f.gate.state.publicKey,released.sealed,label+'|recover|'+a.proof.nonce),bundle);
 await assert.rejects(open((await ephemeral()).privateKey,f.gate.state.publicKey,released.sealed,label+'|recover|'+a.proof.nonce));
 assert.equal((await post(f.gate,'cancel',await recoveryControl(bundle.dk,'cancel',pending.id,f.time()))).status,409);
});
test('existing devices discover and cancel a recovery; cancellation survives restart and proof replay',async()=>{
 const f=await fixture(),a=await recover(),pending=await post(f.gate,'dkim',a.proof);
 const visible=await post(f.gate,'status',await recoveryControl(bundle.dk,'status',undefined,f.time()));
 assert.deepEqual(visible.pending,{id:pending.id,releaseAt:pending.releaseAt});
 assert.equal((await post(f.gate,'cancel',await recoveryControl(bundle.dk,'cancel',pending.id,f.time()))).pending,null);
 await f.restart();f.advance(delay);
 assert.equal((await post(f.gate,'release',{id:pending.id})).status,410);
 assert.equal((await post(f.gate,'dkim',a.proof)).status,410);
 assert.equal((await post(f.gate,'status',await recoveryControl(bundle.dk,'status',undefined,f.time()))).pending,null);
 const next=await post(f.gate,'dkim',(await recover()).proof);
 assert.equal(next.releaseAt,f.time()+delay);
 assert.equal((await post(f.gate,'cancel',await recoveryControl(bundle.dk,'cancel',pending.id,f.time()))).status,409,'old cancellation cannot cancel a new recovery');
});
test('recovery control authenticates the DK holder, action, request id and freshness',async()=>{
 const f=await fixture(),pending=await post(f.gate,'dkim',(await recover()).proof);
 const valid=await recoveryControl(bundle.dk,'cancel',pending.id,f.time());
 assert.equal((await post(f.gate,'cancel',{...valid,auth:(await recoveryControl(random(),'cancel',pending.id,f.time())).auth})).status,403);
 assert.equal((await post(f.gate,'cancel',await recoveryControl(bundle.dk,'status',pending.id,f.time()))).status,403);
 assert.equal((await post(f.gate,'cancel',{...valid,id:'different'})).status,403);
 f.advance(60_001);
 assert.equal((await post(f.gate,'cancel',valid)).status,403);
 assert.equal((await post(f.gate,'status',await recoveryControl(bundle.dk,'status',undefined,f.time()))).pending.id,pending.id);
});
test('retired email-code endpoints cannot enroll or release keys',async()=>{
 const f=await fixture();
 Object.assign(f.state(),{accounts:{oldWrap:{}},challenges:{oldCode:{}},limits:{oldGuesses:{}}});
 await f.restart();
 assert.equal(f.state().accounts,undefined);assert.equal(f.state().challenges,undefined);assert.equal(f.state().limits,undefined);
 for(const path of ['request','confirm'])assert.equal((await post(f.gate,path,{email,purpose:'recover',code:'123456'})).status,404);
});

test('client keeps recovery pending until release and verifies the gate again before opening keys',async t=>{
 const {createEmailGate}=await import('./email-gate-client.mjs');
 const f=await fixture(),a=await recover(),context={...a.proof,...a.pair,gatePublicKey:f.gate.state.publicKey};
 const client=createEmailGate({base:'https://private-agent.example'});let verified=0;
 t.mock.method(client,'verify',async()=>{verified++;return {publicKey:f.gate.state.publicKey};});
 t.mock.method(globalThis,'fetch',async(url,init)=>f.gate.handle(new Request(url,init)));
 const pending=await client.confirmDkim(context,'signed headers');
 assert.equal(pending.pending,true);assert.equal(pending.dk,undefined);
 const saved=structuredClone({...context,...pending});
 assert.equal((await client.release(saved)).pending,true);
 f.advance(delay);
 assert.deepEqual(await client.release(saved),bundle);
 assert.equal(verified,2);
});
