// SYNTHETIC authority controls. No genuine proof, acceptance or funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {sha} from '../bounty-demo/core.mjs';
import {encoded} from './original-report.mjs';
import {parseOutputBundle,expandOutputBundle,OUTPUT_BUNDLE} from './output-bundle.mjs';
import {syntheticAdapterFixture,syntheticResultTar} from './adapter-fixture.mjs';
import {AcceptanceAdapter} from './acceptance-adapter.mjs';
const files=()=>({'checks.json':encoded({ok:true}),'public-input-audit.json':Buffer.from('SYNTHETIC audit'),'trace.zip':Buffer.from('SYNTHETIC trace')});
const mapping=f=>Object.fromEntries(Object.keys(f).map(k=>[k,k]));
const native=f=>({'artifact:result-files':syntheticResultTar(f),'artifact:stage-checks':f['checks.json'],'artifact:public-input-audit':f['public-input-audit.json']});
function checksum(raw){raw.fill(32,148,156);raw.write(raw.subarray(0,512).reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');return raw;}
function resignOutputs(f,stage,mutate){
 f.resignOriginal(stage,(report,o)=>{
  mutate(o.outputs);const r=JSON.parse(o.receiptBytes);
  for(const a of r.outputs.artifacts){const b=o.outputs['artifact:'+a.name];a.bytes=b.length;a.sha256=sha(b);}
  o.receiptBytes=encoded(r);report.subject.receipt_sha256=sha(o.receiptBytes);
  const body={attestation:null};for(const k of ['base_vm','base_vm_launch','harness_sha256','manifest_sha256','observed','outputs','run_id','runtime_inputs_commitment'])body[k]=r[k];
  report.subject.receipt_evidence_sha256=sha(encoded(['dsmack.receipt-evidence/4',body]));
 });
}
test('strict result bundle preserves all logical bytes and canonical manifest',()=>{const f=files(),r=parseOutputBundle(syntheticResultTar(f));assert.deepEqual(r.files,f);assert.deepEqual(expandOutputBundle(native(f),OUTPUT_BUNDLE,mapping(f)),r);});
for(const [label,mutate] of [
 ['checksum',b=>{b[10]^=1;return b;}],
 ['symlink',b=>{b[156]=50;return checksum(b);} ],
 ['directory',b=>{b[156]=53;return checksum(b);} ],
 ['PAX',b=>{b[156]=120;return checksum(b);} ],
 ['path alias',b=>{b.fill(0,0,100);b.write('../checks.json');return checksum(b);} ],
 ['metadata',b=>{b[265]=65;return checksum(b);} ],
 ['mode',b=>{b.write('0000755\0',100,8,'ascii');return checksum(b);} ],
 ['high-bit octal',b=>{b[108]=0xb0;return checksum(b);} ],
 ['content hash',b=>{b[512]^=1;return b;}],
 ['trailing block',b=>Buffer.concat([b,Buffer.alloc(512)])],
 ['missing terminator',b=>b.subarray(0,-512)],
 ['duplicate member',b=>{const size=parseInt(b.subarray(124,135).toString(),8),end=512+Math.ceil(size/512)*512;return Buffer.concat([b.subarray(0,end),b]);}],
 ])test('result bundle refuses '+label,()=>assert.throws(()=>parseOutputBundle(mutate(syntheticResultTar(files())))));
test('manifest self-inclusion, archive budget and member-count overflow refuse',()=>{
 assert.throws(()=>parseOutputBundle(syntheticResultTar({...files(),'output-manifest.json':Buffer.from('self')})));
 assert.throws(()=>parseOutputBundle(Buffer.alloc(16*1024*1024+512)));
 assert.throws(()=>parseOutputBundle(syntheticResultTar(Object.fromEntries(Array.from({length:256},(_,i)=>['file'+String(i).padStart(3,'0'),Buffer.alloc(0)])))));
});
test('logical map and native duplicates cannot pick conflicting truth',()=>{
 const f=files(),n=native(f);assert.throws(()=>expandOutputBundle({...n,'artifact:stage-checks':Buffer.from('different')},OUTPUT_BUNDLE,mapping(f)));
 assert.throws(()=>expandOutputBundle(n,OUTPUT_BUNDLE,{...mapping(f),'missing.json':'missing.json'}));
 assert.throws(()=>expandOutputBundle(n,OUTPUT_BUNDLE,{...mapping(f),'checks.json':'trace.zip'}));
 assert.throws(()=>expandOutputBundle({...n,'artifact:unselected':Buffer.from('extra')},OUTPUT_BUNDLE,mapping(f)));
});
test('complete ten-stage bundled originals join and source delivery stays authenticated',()=>{
 const f=syntheticAdapterFixture({bundledOutputs:true});try{const a=new AcceptanceAdapter(f),r=a.evaluate(f.attemptId,f.input);assert.equal(JSON.parse(r.reportBytes).accepted,true);assert.equal(sha(r.bundleBytes),f.admissions[f.attemptId].task.bundle_sha256);assert.equal(f.store.attempt(f.attemptId).state,'submitted');}finally{f.store.close();}
});
test('native original-byte authentication runs before archive parsing',()=>{
 const f=syntheticAdapterFixture({bundledOutputs:true});try{f.input.originals[0].outputs['artifact:result-files']=Buffer.from('not a tar');assert.throws(()=>new AcceptanceAdapter(f).evaluate(f.attemptId,f.input),/authenticated output bytes/);}finally{f.store.close();}
});
for(const [label,mutate] of [
 ['malformed tar',o=>{o['artifact:result-files']=Buffer.from('not a tar');}],
 ['duplicate disagreement',o=>{o['artifact:stage-checks']=Buffer.from('false native checks');}],
 ['missing logical checks',o=>{const f=parseOutputBundle(o['artifact:result-files']).files;delete f['checks.json'];o['artifact:result-files']=syntheticResultTar(f);}],
 ['extra logical file',o=>{const f=parseOutputBundle(o['artifact:result-files']).files;f['unselected.json']=Buffer.from('extra');o['artifact:result-files']=syntheticResultTar(f);}],
 ['wrong delivered source',o=>{const f=parseOutputBundle(o['artifact:result-files']).files;f['source-bundle']=Buffer.from('swapped');o['artifact:result-files']=syntheticResultTar(f);}],
 ])test('even legitimate synthetic signer cannot admit '+label,()=>{
 const f=syntheticAdapterFixture({bundledOutputs:true});try{resignOutputs(f,label==='wrong delivered source'?'primary-review':'base-1',mutate);assert.throws(()=>new AcceptanceAdapter(f).evaluate(f.attemptId,f.input));assert.equal(f.store.attempt(f.attemptId).state,'submitted');}finally{f.store.close();}
});
