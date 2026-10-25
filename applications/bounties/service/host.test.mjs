import test from 'node:test';import assert from 'node:assert/strict';import {mkdtempSync,rmSync,readFileSync,realpathSync,writeFileSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {createServer} from 'node:http';import {createHandler} from './host.mjs';import {sha} from './core.mjs';
const H='a'.repeat(64),task={slug:'board-undo-testnet-1',repository:'amiller/bounty-arcade',policy_sha256:H,app_policy_sha256:H,chain_id:84532,contract:'0x'+'3'.repeat(40),task_id:'11'};
test('instances keep task, database and HTTP prefix separate',async t=>{
 const roots=[mkdtempSync(join(tmpdir(),'bounty-one-')),mkdtempSync(join(tmpdir(),'bounty-two-'))];const instances=[];
 t.after(async()=>{for(const {s,h}of instances){await new Promise(r=>s.close(r));h.close();}for(const root of roots)rmSync(root,{recursive:true});});
 for(const [i,root]of roots.entries()){
  const raw=Buffer.from('{"task":'+i+',"text":"exact ✓ bytes"}\n');writeFileSync(join(root,'terms.json'),raw);writeFileSync(join(root,'policy.json'),raw);
  const prefix='/bounty-'+i,h=createHandler({root,documentsRoot:root,task:{...task,slug:task.slug+'-'+i},origin:'https://example.org',basePath:prefix,worker_token_sha256:H,cast:{path:realpathSync('/bin/true'),sha256:sha(readFileSync('/bin/true'))}});const s=createServer(h);instances.push({s,h});await new Promise(r=>s.listen(0,'127.0.0.1',r));
  const base='http://127.0.0.1:'+s.address().port;
  assert.equal((await(await fetch(base+prefix+'/api/task')).json()).slug,task.slug+'-'+i);
  assert.equal((await(await fetch(base+'/api/task')).json()).slug,task.slug+'-'+i);assert.notEqual((await fetch(base+'/arcade-pilot/api/task')).status,200);for(const name of ['terms.json','policy.json']){const r=await fetch(base+prefix+'/'+name);assert.deepEqual(Buffer.from(await r.arrayBuffer()),raw);const head=await fetch(base+'/'+name,{method:'HEAD'});assert.equal(head.status,200);assert.equal(Number(head.headers.get('content-length')),raw.length);assert.equal((await head.arrayBuffer()).byteLength,0);}assert.notEqual((await fetch(base+prefix+'/terms.json?other=file')).status,200);
 }
});
