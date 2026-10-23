// Trusted primary review supervisor. Candidate assets are bytes served to
// Chromium, never imported, required, evaluated or executed in host Node.
import {createServer} from 'node:http';
import {readFile,lstat,readdir,mkdir,writeFile,copyFile,realpath} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical,sha,requireThat} from './suite-contract.mjs';
import {bounded,manifest} from './browser-driver.mjs';
import {verifyLogicCoverage} from './primary-logic-admission.mjs';
import {BROWSER,INVENTORY,emptyChecks,admitReport,checksFromReport,selectedMedia} from './primary-contract.mjs';
const HERE=path.dirname(fileURLToPath(import.meta.url));
const FIXED='/opt/bounty-judges/fixed-baseline';
const ACTIVE_GROUPS=new Set();
export function groupEmpty(pgid){
  try{process.kill(-pgid,0);return false;}catch(error){if(error.code==='ESRCH')return true;throw error;}
}
export async function quiesceGroup(pgid,ms=3000){
  if(groupEmpty(pgid)){ACTIVE_GROUPS.delete(pgid);return true;}
  try{process.kill(-pgid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}
  const end=Date.now()+ms;
  while(Date.now()<end){if(groupEmpty(pgid)){ACTIVE_GROUPS.delete(pgid);return true;}await new Promise(resolve=>setTimeout(resolve,25));}
  return false;
}
async function cancelActive(){
  const results=await Promise.all([...ACTIVE_GROUPS].map(pgid=>quiesceGroup(pgid)));
  return results.every(Boolean);
}
export async function snapshotCandidate(root){
  requireThat((await lstat(root)).isDirectory() && !(await lstat(root)).isSymbolicLink(),'candidate root type');
  const assets=new Map(),files=[];let total=0,members=0;
  async function walk(directory,prefix=''){
    for(const name of (await readdir(directory)).sort()){
      requireThat(/^[A-Za-z0-9_.@+-]+$/.test(name) && !['.git','.','..'].includes(name),'candidate path');
      requireThat(++members<=20000,'candidate membership bound');
      const file=path.join(directory,name),relative=prefix+name,stat=await lstat(file);
      if(stat.isDirectory()){await walk(file,relative+'/');continue;}
      requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.nlink===1 && stat.size<=2*1024*1024
        && [0o644,0o755].includes(stat.mode&0o777),'candidate regular file/mode/size');
      const bytes=await readFile(file);total+=bytes.length;
      requireThat(bytes.length===stat.size && total<=32*1024*1024 && files.length<10000,'candidate byte bound');
      files.push({path:relative,mode:stat.mode&0o777,bytes:bytes.length,sha256:sha(bytes)});
      assets.set('/'+relative,bytes);
    }
  }
  await walk(root);files.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  return {assets,files,tree_sha256:sha(Buffer.concat([Buffer.from('dsmack-bounty-source-tree/1\0'),Buffer.from(canonical(files))]))};
}
export function primaryHandler(assets){return (req,res)=>{
  if(req.method!=='GET'){res.writeHead(404);res.end();return;}
  if(req.url==='/favicon.ico'){res.writeHead(204);res.end();return;}
  if(req.url==='/__primary_logic__/'){res.writeHead(200,{'Content-Type':'text/html'});res.end('<!doctype html><title>Trusted logic probe</title>');return;}
  const key=req.url.endsWith('/')?req.url+'index.html':req.url,bytes=assets.get(key);
  if(!bytes){res.writeHead(404);res.end();return;}
  const types={'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.gpx':'application/gpx+xml','.svg':'image/svg+xml','.json':'application/json','.png':'image/png'};
  res.writeHead(200,{'Content-Type':types[path.extname(key)]||'application/octet-stream','Cache-Control':'no-store'});res.end(bytes);
};}
export async function stageTests(state,fixed=FIXED,source=HERE){
  const destination=path.join(state,'primary-tests');await mkdir(destination);
  const provenance=[];
  for(const test of BROWSER){
    const file=path.join(fixed,test.source),stat=await lstat(file);
    requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size<=65536,'fixed spec file');
    const bytes=await readFile(file);requireThat(sha(bytes)===test.sha256,'fixed browser source digest');
    const original=bytes.toString('utf8'),before="from '@playwright/test'";
    requireThat(original.split(before).length===2,'one fixed dependency import');
    const transformed=original.replace(before,"from '/opt/bounty-judges/primary-fixtures.mjs'");
    await writeFile(path.join(destination,test.file),transformed);
    provenance.push({id:test.id,source_path:test.source,source_sha256:test.sha256,
      transformed_sha256:sha(Buffer.from(transformed)),operation:'replace-one-Playwright-import-with-trusted-fixture'});
  }
  for(const name of ['primary-feature.spec.mjs','primary-logic.spec.mjs'])await copyFile(path.join(source,name),path.join(destination,name));
  const coverage=await verifyLogicCoverage(source);
  const originals=path.join(source,'primary-original'),raw=await readFile(path.join(originals,'SOURCE.json'));
  requireThat(sha(raw)===coverage.original_manifest_sha256,'original logic source manifest pin');
  const original=JSON.parse(raw);
  requireThat(original.commit==='5c76d40e77db1f4864dabd4b9398d02589cff330' && original.files.length===7,'original logic source/fixture closure');
  for(const row of original.files){
    requireThat(/^apps\/(board|flight|puzzle|routes)\/(test\/logic\.test\.js|levels\.json|samples\/[a-z-]+\.gpx)$/.test(row.path),'original logic fixture path');
    const file=path.join(originals,row.path),stat=await lstat(file);
    requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size<=65536,'original logic fixture type/size');
    const bytes=await readFile(file);requireThat(bytes.length===row.bytes&&sha(bytes)===row.sha256,'original logic fixture digest');
  }
  provenance.push({id:'original-logic-coverage',source_manifest_sha256:sha(raw),
    renderer_adaptation_admitted:true,required_case_counts:Object.fromEntries(Object.entries(coverage.groups).map(([app,g])=>[app,g.required_case_ids.length]))});
  return provenance;
}
export async function runOwned(argv,{state,stdoutLimit=262144,stderrLimit=65536,wallMs=490000}){
  return await new Promise((resolve,reject)=>{
    const child=spawn(argv[0],argv.slice(1),{cwd:state,detached:true,env:{PATH:'/usr/bin:/bin',HOME:state,TMPDIR:state,
      PLAYWRIGHT_BROWSERS_PATH:process.env.PLAYWRIGHT_BROWSERS_PATH||'/ms-playwright'},stdio:['ignore','pipe','pipe']});
    const chunks={stdout:[],stderr:[]},sizes={stdout:0,stderr:0};let failure=null,cleanup=Promise.resolve(false);
    if(child.pid)ACTIVE_GROUPS.add(child.pid);
    const kill=()=>{try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')failure=String(error.message);}};
    const timer=setTimeout(()=>{failure='primary runner deadline';kill();},wallMs);
    for(const [stream,limit] of [['stdout',stdoutLimit],['stderr',stderrLimit]])child[stream].on('data',chunk=>{
      const remaining=Math.max(0,limit-sizes[stream]);chunks[stream].push(chunk.subarray(0,remaining));sizes[stream]+=chunk.length;
      if(sizes[stream]>limit){failure='primary runner '+stream+' bound';kill();}
    });
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',()=>{
      // 'exit' reaps the direct child; 'close' can wait forever for a hanging
      // descendant holding stdout. Detect and kill that group at exit, then
      // independently confirm emptiness before resolving any successful run.
      if(!groupEmpty(child.pid))failure=failure||'descendants outlived primary runner';
      cleanup=quiesceGroup(child.pid);
    });
    child.once('close',async(code,signal)=>{clearTimeout(timer);
      const cleanup_confirmed=await cleanup;
      if(!cleanup_confirmed)failure=failure||'owned process group not quiescent';
      resolve({code,signal,failure,cleanup_confirmed,
        stdout:Buffer.concat(chunks.stdout),stderr:Buffer.concat(chunks.stderr)});
    });
  });
}
export async function exportMedia(report,state,output){
  let total=0;const names=[];
  for(const row of report.tests)for(const item of selectedMedia(row,state)){
    const stat=await lstat(item.source),actual=await realpath(item.source);
    requireThat(actual.startsWith(path.resolve(state,'primary-results')+path.sep)
      && stat.isFile() && !stat.isSymbolicLink() && stat.size>0 && stat.size<=16*1024*1024,'media type/size/path');
    total+=stat.size;requireThat(total<=60*1024*1024,'primary media total bound');
    await copyFile(item.source,path.join(output,item.name));names.push(item.name);
  }
  return names.sort();
}
export async function runPrimary({candidate,expectedTree,state,output,fixed=FIXED,source=HERE,
  run=runOwned,serverFactory=handler=>createServer(handler),wallMs=540000}){
  await mkdir(output,{recursive:true});requireThat((await readdir(output)).length===0,'empty primary output required');
  let checks=emptyChecks(),server;
  const details={schema:'dsmack-bounty-primary-details/1',status:'infrastructure_failed',errors:[],
    runtime_uid:process.getuid(),runtime_gid:process.getgid(),tests:[],source_tree_sha256:null,
    execution_closure_joined:false,logic_renderer_adaptation_admitted:false,accepted:false};
  const save=()=>{writeFileSync(path.join(output,'checks.json'),canonical(checks));writeFileSync(path.join(output,'primary-details.json'),canonical(details));};
  const watchdog=setTimeout(async()=>{
    checks=emptyChecks();details.status='infrastructure_failed';details.errors.push('global primary deadline');try{save();}catch{}
    try{details.errors.push(await cancelActive()?'owned groups killed and quiescent':'owned group cleanup unconfirmed');}
    catch(error){details.errors.push('cleanup error: '+String(error.message));}
    save();process.exit(2);
  },wallMs);
  try{
    requireThat(process.getuid()===1000 && process.getgid()===1000,'primary runtime UID/GID1000');
    requireThat((await readdir(state)).length===0,'fresh empty primary state required');
    const snapshot=await snapshotCandidate(candidate);details.source_tree_sha256=snapshot.tree_sha256;
    requireThat(snapshot.tree_sha256===expectedTree,'independently pinned candidate tree');
    const provenance=await stageTests(state,fixed,source);
    details.logic_renderer_adaptation_admitted=true;
    await writeFile(path.join(output,'primary-source-transform.json'),canonical(provenance));
    server=serverFactory(primaryHandler(snapshot.assets));
    await bounded(new Promise((resolve,reject)=>{server.once('error',reject);server.listen(4173,'127.0.0.1',resolve);}));
    const execution=await run(['/usr/bin/node','/opt/checker/node_modules/@playwright/test/cli.js','test',
      '--config=/opt/bounty-judges/primary.config.mjs'],{state});
    await writeFile(path.join(output,'primary-stdout.txt'),execution.stdout);
    await writeFile(path.join(output,'primary-stderr.txt'),execution.stderr);
    details.cleanup_confirmed=execution.cleanup_confirmed===true;
    requireThat(!execution.failure && execution.cleanup_confirmed===true && execution.signal===null && [0,1].includes(execution.code),'primary runner infrastructure outcome: '+(execution.failure||'cleanup/exit'));
    const raw=await readFile(path.join(state,'primary-raw-report.json'));
    await writeFile(path.join(output,'primary-raw-report.json'),raw);
    const report=admitReport(raw,{captureInfrastructure:true});
    requireThat(execution.code===(report.status==='passed'?0:1),'runner exit/report mismatch');
    details.tests=report.tests.map(row=>({id:INVENTORY.find(t=>t.file===row.file&&t.title===row.title).id,status:row.status}));
    await exportMedia(report,state,output);
    admitReport(raw); // infrastructure annotations can retain media, never pass
    await bounded(new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())));server=null;
    checks=checksFromReport(report);
    details.status=report.status==='passed'?'completed':'assertion_failed';
  }catch(error){checks=emptyChecks();details.errors.push(String(error.message).slice(0,2000));}
  finally{
    if(server)await bounded(new Promise(resolve=>server.close(resolve))).catch(error=>details.errors.push(String(error.message)));
    if(!await cancelActive()){checks=emptyChecks();details.status='infrastructure_failed';details.errors.push('owned groups remain nonquiescent');}
    save();
  }
  try{await writeFile(path.join(output,'output-manifest.json'),canonical(await manifest(output)),{flag:'wx'});}
  catch(error){checks=emptyChecks();details.status='infrastructure_failed';details.errors.push('output manifest: '+String(error.message));save();}
  clearTimeout(watchdog);return {checks,details};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{
    requireThat(process.argv.length===3 && /^[a-f0-9]{64}$/.test(process.argv[2]),'expected candidate tree SHA256 argument required');
    const pkg=JSON.parse(await readFile('/opt/checker/node_modules/playwright/package.json','utf8'));
    requireThat(pkg.version==='1.64.0','admitted Playwright version');
    const {details}=await runPrimary({candidate:'/candidate',expectedTree:process.argv[2],state:'/workspace/state',output:'/workspace/artifacts'});
    process.exitCode=details.status==='completed'?0:details.status==='assertion_failed'?1:2;
  }catch(error){process.stderr.write(String(error.message)+'\n');process.exitCode=2;}
}
