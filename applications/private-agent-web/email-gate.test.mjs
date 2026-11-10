import {test} from 'node:test';
import assert from 'node:assert/strict';
test('dstack quote logs with omitted digests replay their canonical measured events',async()=>{
 const {replayGateEvents}=await import('./email-gate-client.mjs');
 const {createHash}=await import('node:crypto');
 const events=[{imr:3,event_type:134217729,event:'app-id',event_payload:'abcd',digest:''},{imr:3,event_type:134217729,event:'system-ready',event_payload:'',digest:''}];
 let expected=Buffer.alloc(48);
 for(const e of events){const type=Buffer.alloc(4);type.writeUInt32LE(e.event_type);const digest=createHash('sha384').update(type).update(':'+e.event+':').update(Buffer.from(e.event_payload,'hex')).digest();expected=createHash('sha384').update(expected).update(digest).digest();}
 const result=await replayGateEvents(events);
 assert.deepEqual(Buffer.from(result.mr),expected);assert.equal(result.ready,true);assert.equal(result.boot['app-id'],'abcd');
 await assert.rejects(replayGateEvents([{...events[0],digest:'00'.repeat(48)}]),/digest differs/);
});

test('DKIM polling waits through missing mail, pending ingestion, deploy failures and a lost connection',async t=>{
 const {createEmailGate}=await import('./email-gate-client.mjs');
 const {setImmediate}=await import('node:timers/promises');
 t.mock.timers.enable({apis:['Date','setTimeout']});
 const replies=[404,202,500,502,503,'offline',200],calls=[];
 t.mock.method(globalThis,'fetch',async()=>{
  const status=replies[calls.length];calls.push(status);
  if(status==='offline')throw new TypeError('fetch failed');
  return new Response(JSON.stringify({headers:status===200?'signed Gmail headers':'not ready'}),{status});
 });
 let waiting=0;
 const result=createEmailGate({}).waitDkim({nonce:'test',gatePublicKey:{},email:'test@gmail.com'},{onWaiting:()=>waiting++});
 for(let n=0;n<replies.length-1;n++){
  await setImmediate();
  assert.equal(waiting,n+1);
  t.mock.timers.tick(2000);
 }
 assert.equal(await result,'signed Gmail headers');
 assert.deepEqual(calls,replies);
});

test('DKIM polling reports the receiver error for non-404 client failures',async t=>{
 const {createEmailGate}=await import('./email-gate-client.mjs');
 t.mock.method(globalThis,'fetch',async()=>new Response(JSON.stringify({error:'Recovery request refused'}),{status:403}));
 await assert.rejects(createEmailGate({}).waitDkim({nonce:'test',gatePublicKey:{},email:'test@gmail.com'}),/Recovery request refused/);
});

test('DKIM polling stops waiting after five minutes of deploy failures',async t=>{
 const {createEmailGate}=await import('./email-gate-client.mjs');
 const {setImmediate}=await import('node:timers/promises');
 t.mock.timers.enable({apis:['Date','setTimeout']});
 t.mock.method(globalThis,'fetch',async()=>new Response('Deploying',{status:503}));
 const result=createEmailGate({}).waitDkim({nonce:'test',gatePublicKey:{},email:'test@gmail.com'});
 const rejected=assert.rejects(result,/within 5 minutes.*test@gmail.com/);
 await setImmediate();
 t.mock.timers.tick(5*60_000);
 await rejected;
});
