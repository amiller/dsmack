// EXPLICITLY INVOKED SYNTHETIC HTTP CONTROL. Ephemeral fake authorities only.
// Starts an owned loopback listener and stops it. No genuine evidence or funds.
import assert from 'node:assert/strict';
import { AcceptanceAdapter } from './acceptance-adapter.mjs';
import { createAcceptanceApplication } from './acceptance-service.mjs';
import { syntheticAdapterFixture } from './adapter-fixture.mjs';
const f=syntheticAdapterFixture();let active=f.input;
const adapter=new AcceptanceAdapter(f),evaluated=adapter.evaluate(f.attemptId,f.input);
const certificate=f.certificate(evaluated.reportBytes),operatorToken='SYNTHETIC-HTTP-CONTROL-ONLY-1234567890';
const server=createAcceptanceApplication({...f,operatorToken,loadInput:async()=>active});
try {
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const origin='http://127.0.0.1:'+server.address().port;
  const rows=[];
  const post=async(label,cert,expectedStatus)=>{
    const response=await fetch(origin+'/api/attempts/'+f.attemptId+'/verdict',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+operatorToken},body:JSON.stringify(cert)});
    assert.equal(response.status,expectedStatus);await response.json();rows.push({case:label,http_status:response.status,state:f.store.attempt(f.attemptId).state});
  };
  active={...f.input,originals:[f.input.originals[9]]};await post('missing nine original child proofs',certificate,400);
  active=f.input;await post('certificate for six-check diagnostic bytes',f.certificate(Buffer.from('SYNTHETIC diagnostic')),403);
  await post('complete SYNTHETIC ten-stage graph',certificate,200);
  f.store.now=()=>1300;await post('same admitted certificate after expiry',certificate,200);
  assert.equal(f.store.attempt(f.attemptId).verdict_received_at,1000);
  console.log(JSON.stringify({schema:'dsmack-synthetic-acceptance-http-walkthrough/1',synthetic:true,genuine_evidence_qualified:false,payment_received:false,first_admission:1000,cases:rows},null,2));
} catch(error) {
  console.error('SYNTHETIC local HTTP walkthrough failed: '+(error.code??error.message));process.exitCode=1;
} finally {
  if(server.listening)await new Promise(resolve=>server.close(resolve));f.store.close();
}
