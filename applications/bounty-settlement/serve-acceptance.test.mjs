// Synthetic controls only, never genuine VM proof or payment.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,chmodSync,symlinkSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {sha} from '../bounty-demo/core.mjs';
import {syntheticAdapterFixture} from './adapter-fixture.mjs';
import {AcceptanceAdapter} from './acceptance-adapter.mjs';
import {readPinned,readEvidence,startAcceptance} from './serve-acceptance.mjs';
const root=mkdtempSync(join(homedir(),'dsmack-acceptance-control-'));let serial=0;
const put=b=>{b=Buffer.isBuffer(b)?b:Buffer.from(JSON.stringify(b));const path=join(root,String(serial++));writeFileSync(path,b,{mode:0o600});return {path,bytes:b.length,sha256:sha(b)};};
const f=syntheticAdapterFixture({dbPath:join(root,'state.sqlite'),clock:()=>Math.floor(Date.now()/1000)});
const snapshot=()=>put({schema:'dsmack-bounty-original-evidence-files/1',request:put(f.input.requestBytes),results:put(f.input.resultsBytes),originals:f.input.originals.map(s=>({stage_id:s.stage_id,report:put(s.reportBytes),receipt:put(s.receiptBytes),manifest:put(s.manifestBytes),public_inputs:put(s.publicInputsBytes),outputs:Object.fromEntries(Object.entries(s.outputs).map(([k,b])=>[k,put(b)]))}))});
test('original-evidence startup and bounded immutable staging',async t=>{
 try{
  await t.test('pin reader refuses substituted bytes',()=>{const d=put(Buffer.from('original'));writeFileSync(d.path,'tampered');assert.throws(()=>readPinned(d));});
  await t.test('pin reader refuses symlink aliases',()=>{const d=put(Buffer.from('x')),path=join(root,'alias');symlinkSync(d.path,path);assert.throws(()=>readPinned({...d,path}));});
  await t.test('private operator token refuses public modes',()=>{const d=put(Buffer.from('secret'));chmodSync(d.path,0o644);assert.throws(()=>readPinned(d,{privateFile:true}));});
  const desc=snapshot();
  await t.test('full staged input preserves every original byte',()=>assert.deepEqual(readEvidence(desc),f.input));
  await t.test('nine-stage evidence refuses before admission',()=>{const d=JSON.parse(readPinned(desc));d.originals.pop();assert.throws(()=>readEvidence(put(d)));});
  const evaluation=new AcceptanceAdapter(f).evaluate(f.attemptId,f.input),certificate=f.certificate(evaluation.reportBytes,{issued_at:Math.floor(Date.now()/1000),expires_at:Math.floor(Date.now()/1000)+600});
  // Preserve actual store, restart through explicit genuine adapter factory.
  f.store.close();chmodSync(join(root,'state.sqlite'),0o600);
  const config={schema:'dsmack-bounty-acceptance-service/1',state_path:join(root,'state.sqlite'),operator_token:put(Buffer.from('SYNTHETIC-operator-capability-1234567890')),verifier_keys:{'synthetic-application':f.appKey},report_keys:f.reportKeys,admissions:f.admissions,evidence:{[f.attemptId]:desc},repositories:['amiller/bounty-arcade'],port:18787};
  await t.test('startup rejects missing original report authority',()=>assert.throws(()=>startAcceptance(JSON.stringify({...config,report_keys:{}}))));
  await t.test('startup rejects unknown evidence assignment',()=>assert.throws(()=>startAcceptance(JSON.stringify({...config,evidence:{['a'.repeat(32)]:desc}}))));
  await t.test('actual loopback service accepts only fully joined synthetic evidence',async()=>{
   const {server,store}=startAcceptance(JSON.stringify(config));
   try{
    await new Promise((ok,bad)=>{server.once('error',bad);server.listen(0,'127.0.0.1',ok);});
    const post=cert=>fetch('http://127.0.0.1:'+server.address().port+'/api/attempts/'+f.attemptId+'/verdict',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer SYNTHETIC-operator-capability-1234567890'},body:JSON.stringify(cert)});
    assert.equal((await post(f.certificate(Buffer.from('diagnostic')))).status,403);
    assert.equal(store.attempt(f.attemptId).state,'submitted');
    assert.equal((await post(certificate)).status,200);assert.equal(store.attempt(f.attemptId).state,'verified');
   }finally{await new Promise(ok=>server.close(ok));store.close();}
  });
 }finally{rmSync(root,{recursive:true,force:true});}
});
