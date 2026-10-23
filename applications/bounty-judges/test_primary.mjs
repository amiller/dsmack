// Socket-free/source-only controls; no actual browser or candidate JS execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,copyFile,chmod} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {EventEmitter} from 'node:events';
import {fileURLToPath} from 'node:url';
import {canonical,sha} from './suite-contract.mjs';
import {INVENTORY,emptyChecks,admitReport,checksFromReport,selectedMedia} from './primary-contract.mjs';
import {verifyLogicCoverage} from './primary-logic-admission.mjs';
import {snapshotCandidate,primaryHandler,stageTests,exportMedia,runOwned,runPrimary,groupEmpty} from './primary-driver.mjs';
const HERE=path.dirname(fileURLToPath(import.meta.url));
const FIXED=path.resolve(HERE,'../bounty-recipes/board-search-pilot-v1/fixed-baseline');
function report(){return {schema:'dsmack-bounty-primary-raw/1',status:'passed',errors:[],
  discovered:INVENTORY.map(({file,title})=>({file,title})),tests:INVENTORY.map(({file,title})=>({
    file,title,status:'passed',expected_status:'passed',retry:0,annotations:[],errors:[],attachments:[]}))};}
const admit=value=>admitReport(Buffer.from(canonical(value)));
async function temporary(fn){const root=await mkdtemp(path.join(os.tmpdir(),'primary-control-'));try{return await fn(root);}finally{await rm(root,{recursive:true,force:true});}}
function fakeServer(){const server=new EventEmitter();server.listen=(_port,_host,resolve)=>resolve();server.close=resolve=>resolve();return server;}

test('closed 4+4+6 booleans derive exact actual IDs, independent of report order',()=>{
  const raw=report();raw.tests.reverse();const checks=checksFromReport(admit(raw));
  assert.deepEqual(checks,{schema:'dsmack-bounty-primary-checks/1',fixed_browser_baselines:[true,true,true,true],fixed_logic_baselines:[true,true,true,true],feature_checks:[true,true,true,true,true,true]});
  raw.status='failed';raw.tests.find(row=>row.title==='search-case-insensitive-all-columns').status='failed';
  assert.deepEqual(checksFromReport(admit(raw)).feature_checks,[true,false,true,true,true,true]);
  assert.ok(Object.values(emptyChecks()).slice(1).flat().every(value=>value===false));
});
test('missing, duplicate, skipped, retry, truthy, global-error and self-graded results refuse',()=>{
  for(const change of [r=>r.tests.pop(),r=>r.tests[0]=r.tests[1],r=>r.discovered.pop(),
    r=>r.tests[0].status='skipped',r=>r.tests[0].status=true,r=>r.tests[0].retry=1,
    r=>r.tests[0].expected_status='failed',r=>r.errors.push('browser crashed'),r=>r.status='timedout',
    r=>r.tests[0].annotations.push({type:'primary-infrastructure',description:'original logic suite missing'}),
    r=>r.tests[0].annotations.push({type:'skip'}),r=>r.tests[0].errors.push('teardown failed')]){
    const raw=report();change(raw);assert.throws(()=>admit(raw));
  }
  assert.throws(()=>admitReport(Buffer.from('{"passed":true}')));
  assert.throws(()=>admitReport(Buffer.from(' '+canonical(report()))));
});
test('candidate snapshot hashes source bytes, never executes scripts and blocks links',async()=>temporary(async root=>{
  const candidate=path.join(root,'candidate');await mkdir(candidate);
  const hostile='throw new Error("MUST NOT EXECUTE IN NODE");';
  await writeFile(path.join(candidate,'logic.js'),hostile);await chmod(path.join(candidate,'logic.js'),0o644);
  const result=await snapshotCandidate(candidate);
  assert.equal(result.assets.get('/logic.js').toString(),hostile);
  assert.equal(result.files[0].sha256,sha(Buffer.from(hostile)));
  assert.equal(result.tree_sha256,sha(Buffer.concat([Buffer.from('dsmack-bounty-source-tree/1\0'),Buffer.from(canonical(result.files))])));
  await symlink(path.join(candidate,'logic.js'),path.join(candidate,'linked.js'));
  await assert.rejects(snapshotCandidate(candidate),/regular file/);
}));
test('HTTP handler cannot serve host, query strings, traversal or another origin',()=>{
  const handler=primaryHandler(new Map([['/apps/board/index.html',Buffer.from('candidate')]]));
  for(const [url,method,expected] of [['/apps/board/','GET',200],['/etc/passwd','GET',404],
    ['/apps/board/?secret','GET',404],['/apps/board/../logic.js','GET',404],['/apps/board/','POST',404],
    ['https://remote.invalid/','GET',404],['/__primary_logic__/','GET',200]]){
    let status;handler({url,method},{writeHead:code=>{status=code;},end:()=>{}});assert.equal(status,expected);
  }
});
test('all four original browser sources have exact hashes and ONE explicit import transform',async()=>temporary(async root=>{
  const provenance=await stageTests(root,FIXED,HERE);assert.equal(provenance.length,5);
  for(const row of provenance.slice(0,4)){
    const original=await readFile(path.join(FIXED,row.source_path),'utf8');
    assert.equal(row.source_sha256,sha(Buffer.from(original)));
    assert.equal(await readFile(path.join(root,'primary-tests',row.source_path.replace('.js','.mjs')),'utf8'),
      original.replace("from '@playwright/test'","from '/opt/bounty-judges/primary-fixtures.mjs'"));
  }
  const bad=path.join(root,'bad');await mkdir(bad);
  for(const name of ['board','flight','puzzle','routes'])await copyFile(path.join(FIXED,name+'.spec.js'),path.join(bad,name+'.spec.js'));
  await writeFile(path.join(bad,'board.spec.js'),'process.exit(0)');
  const state=path.join(root,'state');await mkdir(state);
  await assert.rejects(stageTests(state,bad,HERE),/source digest/);
}));
test('missing, duplicate, escaping, symlink and empty required media refuse',async()=>temporary(async root=>{
  const state=path.join(root,'state'),output=path.join(root,'output');await mkdir(state);await mkdir(output);
  const results=path.join(state,'primary-results');await mkdir(results);
  const raw=report();for(const row of raw.tests)row.attachments=['screenshot','trace','video'].map(name=>({name,path:path.join(results,row.title.replaceAll(' ','-')+'-'+name)}));
  for(const row of raw.tests)for(const attachment of row.attachments)await writeFile(attachment.path,'media');
  assert.equal((await exportMedia(admit(raw),state,output)).length,42);
  const row=structuredClone(raw.tests[0]);row.attachments.pop();assert.throws(()=>selectedMedia(row,state),/required/);
  row.attachments.push({name:'video',path:'/etc/passwd'});assert.throws(()=>selectedMedia(row,state),/outside/);
  const source=raw.tests[0].attachments[0].path;await rm(source);await symlink('/etc/passwd',source);
  await assert.rejects(exportMedia(admit(raw),state,output),/media type/);
}));
test('owned process group cleanup is confirmed on normal exit; output and deadline failures retained',async()=>temporary(async state=>{
  const normal=await runOwned(['/usr/bin/python3','-c','import sys;sys.stdout.write("original")'],{state,wallMs:1000});
  assert.equal(normal.code,0);assert.equal(normal.failure,null);assert.equal(normal.cleanup_confirmed,true);assert.equal(normal.stdout.toString(),'original');
  const loud=await runOwned(['/usr/bin/python3','-c','import sys,time;sys.stdout.write("x"*65536);sys.stdout.flush();time.sleep(3)'],{state,stdoutLimit:64,wallMs:1000});
  assert.match(loud.failure,/bound/);assert.equal(loud.stdout.length,64);assert.equal(loud.cleanup_confirmed,true);
  const slow=await runOwned(['/usr/bin/python3','-c','import sys,time;sys.stdout.write("partial");sys.stdout.flush();time.sleep(3)'],{state,wallMs:80});
  assert.match(slow.failure,/deadline/);assert.equal(slow.cleanup_confirmed,true);assert.equal(slow.stdout.toString(),'partial');
}));
test('hanging descendants cannot turn a parent exit zero into primary success',async()=>temporary(async state=>{
  const script='import subprocess,sys,os;subprocess.Popen([sys.executable,"-c","import time;time.sleep(3)"]);os._exit(0)';
  const result=await runOwned(['/usr/bin/python3','-c',script],{state,wallMs:1000});
  assert.equal(result.code,0);assert.match(result.failure,/descendants|quiescent/);
  // Cleanup may remain unconfirmed for orphan zombies: such a run stays infra.
}));
test('successful-looking report without media/confirmed cleanup cannot emit true checks',async()=>temporary(async root=>{
  const candidate=path.join(root,'candidate');await mkdir(candidate);await writeFile(path.join(candidate,'index.html'),'candidate');await chmod(path.join(candidate,'index.html'),0o644);
  const expectedTree=(await snapshotCandidate(candidate)).tree_sha256;
  for(const cleanup_confirmed of [false,true]){
    const state=path.join(root,'state-'+cleanup_confirmed),output=path.join(root,'out-'+cleanup_confirmed);await mkdir(state);
    const run=async()=>{await writeFile(path.join(state,'primary-raw-report.json'),canonical(report()));return {code:0,signal:null,failure:null,cleanup_confirmed,stdout:Buffer.from('passed'),stderr:Buffer.alloc(0)};};
    const result=await runPrimary({candidate,expectedTree,state,output,fixed:FIXED,source:HERE,run,serverFactory:fakeServer});
    assert.equal(result.details.status,'infrastructure_failed');assert.deepEqual(result.checks,emptyChecks());
    assert.ok(result.details.errors.length);
  }
}));
test('complete original logic source/case closure is admitted and altered modules refuse',async()=>temporary(async root=>{
 const coverage=await verifyLogicCoverage(HERE);
 assert.deepEqual(Object.values(coverage.groups).map(g=>g.required_case_ids.length),[27,15,26,12]);
 const files=['primary-logic-coverage.json',...Object.values(coverage.groups).map(g=>g.module)];
 for(const name of files)await copyFile(path.join(HERE,name),path.join(root,name));
 const helper=path.join(root,coverage.groups.board.module);
 await writeFile(helper,'export const CASE_IDS=[];');
 await assert.rejects(verifyLogicCoverage(root),/source pin/);
 await copyFile(path.join(HERE,coverage.groups.board.module),helper);
 for(const change of [c=>c.groups.board.admitted=false,c=>c.groups.puzzle.required_case_ids.pop(),c=>c.groups.flight.renderer_assertion_correspondence=[],c=>c.groups.routes.module='../outside.mjs']){
  const changed=structuredClone(coverage);change(changed);await writeFile(path.join(root,'primary-logic-coverage.json'),JSON.stringify(changed));
  await assert.rejects(verifyLogicCoverage(root));
 }
}));
