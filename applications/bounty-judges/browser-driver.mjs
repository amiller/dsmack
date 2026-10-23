// External trusted Playwright interpreter. Candidate JS is never imported here.
import {createServer} from 'node:http';
import {readFile, mkdir, readdir, lstat, writeFile, rename} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical, parseSuite, sha, requireThat, LIMITS, FIXTURE} from './suite-contract.mjs';

export class BehavioralFailure extends Error {}
export async function bounded(promise, ms=LIMITS.actionMs) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject)=>{
    timer=setTimeout(()=>reject(new Error('infrastructure operation timeout')),ms);
  })]); } finally { clearTimeout(timer); }
}
export async function executeStep(page, step, origin, assertionMs=LIMITS.assertionMs) {
  if (step.op === 'navigate') {
    const response=await bounded(page.goto(origin+FIXTURE, {waitUntil:'load'}));
    requireThat(response?.status() === 200, 'fixture navigation failed'); return;
  }
  if (step.op === 'reload') {
    const response=await bounded(page.reload({waitUntil:'load'}));
    requireThat(response?.status() === 200, 'fixture reload failed'); return;
  }
  const locator=page.locator(step.selector);
  if (step.op === 'click' || step.op === 'fill') {
    requireThat(await bounded(locator.count()) === 1, 'action target must be unique');
    await bounded(step.op === 'click' ? locator.click() : locator.fill(step.value)); return;
  }
  const end=Date.now()+assertionMs;
  let actual;
  do {
    const count=await bounded(locator.count());
    if (step.op === 'assert_count') actual=count;
    else if (step.op === 'assert_visible') actual=count === 0 ? false : count === 1
      ? await bounded(locator.isVisible()) : {matches:count};
    else if (count !== 1) actual={matches:count};
    else if (step.op === 'assert_text') actual=await bounded(locator.textContent());
    else if (step.op === 'assert_value') actual=await bounded(locator.inputValue());
    else if (step.op === 'assert_attribute') actual=await bounded(locator.getAttribute(step.name));
    else throw new Error('unadmitted operation');
    if (actual === step.value) return;
    if (Date.now() >= end) break;
    await new Promise(resolve=>setTimeout(resolve,40));
  } while (true);
  // Only a completed, successful browser read with a mismatched value can reach
  // this classification. Playwright errors and operation timeouts propagate.
  throw new BehavioralFailure(`${step.op}: expected ${JSON.stringify(step.value)}, observed ${JSON.stringify(actual).slice(0,500)}`);
}

export async function runTest(page, test, origin, assertionMs) {
  for (let index=0; index<test.steps.length; index++) {
    try { await executeStep(page,test.steps[index],origin,assertionMs); }
    catch (error) {
      return {id:test.id,status:error instanceof BehavioralFailure ? 'assertion_failed' : 'infrastructure_failed',
        step:index,error:String(error.message).slice(0,1000)};
    }
  }
  return {id:test.id,status:'passed'};
}

const ASSETS = {'/apps/board/':'board-index.html','/apps/board/index.html':'board-index.html',
  '/apps/board/logic.js':'board-logic.js','/apps/board/ui.js':'board-ui.js'};
export async function readAssets(root) {
  const rootStat=await lstat(root);
  requireThat(rootStat.isDirectory() && !rootStat.isSymbolicLink(), 'asset root type');
  const result=new Map();
  for (const [url,name] of Object.entries(ASSETS)) {
    const file=path.join(root,name), stat=await lstat(file);
    requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 1024*1024, 'asset type/size');
    result.set(url,{bytes:await readFile(file),type:name.endsWith('.html')?'text/html':'text/javascript'});
  }
  return result;
}
export function fixtureHandler(assets) {
  return (req,res)=>{
    const asset=assets.get(req.url);
    if (req.method !== 'GET' || !asset) { res.writeHead(404); res.end(); return; }
    res.writeHead(200,{'Content-Type':asset.type,'Cache-Control':'no-store',
      'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; worker-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'"});
    res.end(asset.bytes);
  };
}
export function fixtureServer(assets) {
  return createServer(fixtureHandler(assets));
}
export async function manifest(output) {
  const files=[]; let total=0;
  for (const name of (await readdir(output)).sort()) {
    if (name === 'output-manifest.json') continue; // envelope cannot hash itself
    requireThat(/^[a-z][a-z0-9.-]{0,79}$/.test(name), 'output name');
    const stat=await lstat(path.join(output,name));
    requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size <= LIMITS.fileBytes, 'output type/size');
    const bytes=await readFile(path.join(output,name)); total+=bytes.length;
    requireThat(total <= LIMITS.totalBytes, 'total output bound');
    files.push({name,size:bytes.length,sha256:sha(bytes)});
  }
  requireThat(files.length > 0 && files.length <= 64, 'output file count');
  // The envelope is a sibling sidecar, not an entry in its own file set.
  return {schema:'dsmack-bounty-output-manifest/1',files};
}

export async function runBrowser({suiteBytes=null, assets=null, inputRoot=null, output, chromium,
  wallMs=LIMITS.wallMs, serverFactory=fixtureServer}) {
  const checks={schema:'dsmack-bounty-ci-checks/1',browser_started:false,completed:false,
    infrastructure_failed:true,tests:[],suite_sha256:suiteBytes === null ? null : sha(suiteBytes)};
  const details={schema:'dsmack-bounty-driver-details/1',status:'infrastructure_failed',tests:[],errors:[],
    runtime_uid:process.getuid(),runtime_gid:process.getgid(),
    blocked_requests:[],blocked_websockets:0};
  await mkdir(output,{recursive:true});
  requireThat(!(await lstat(output)).isSymbolicLink(), 'output directory link');
  requireThat((await readdir(output)).length === 0, 'output directory must be empty');
  const saveSync=()=>{
    writeFileSync(path.join(output,'checks.json'),canonical(checks));
    writeFileSync(path.join(output,'driver-details.json'),canonical(details));
  };
  // Outer supervisor must also impose a hard process/container deadline and
  // bounded tmpfs. A hard timeout never leaves an earlier successful verdict.
  const watchdog=setTimeout(()=>{
    checks.completed=false; checks.infrastructure_failed=true;
    details.status='infrastructure_failed'; details.errors.push('global deadline; owned cleanup not confirmed');
    saveSync(); process.exit(2);
  },wallMs);
  let browser, server, closing=false, crashed=false;
  try {
    if (suiteBytes === null) {
      const file=path.join(inputRoot,'suite.json'), stat=await lstat(file);
      requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size <= LIMITS.suiteBytes, 'suite file type/size');
      suiteBytes=await readFile(file); checks.suite_sha256=sha(suiteBytes);
    }
    const suite=parseSuite(suiteBytes);
    if (assets === null) assets=await readAssets(inputRoot);
    server=serverFactory(assets);
    await bounded(new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);}));
    const origin=`http://127.0.0.1:${server.address().port}`;
    browser=await bounded(chromium.launch({chromiumSandbox:true,timeout:LIMITS.actionMs}));
    checks.browser_started=true;
    browser.on('disconnected',()=>{if(!closing)crashed=true;});
    for (const [index,test] of suite.tests.entries()) {
      const prefix=`test-${String(index+1).padStart(2,'0')}`;
      let context, page, video, result, scriptError=null;
      try {
        context=await bounded(browser.newContext({viewport:{width:1000,height:720},
          recordVideo:{dir:path.join(output, prefix+'-video'),size:{width:1000,height:720}},
          serviceWorkers:'block',acceptDownloads:false}));
        await bounded(context.route('**/*', route=>{
          const request=route.request();
          // Scheme, host, port, path and method are exact; no remote resource,
          // redirects, websockets, query strings or alternate local fixtures.
          if (request.method() === 'GET' && assets.has(request.url().slice(origin.length))
            && request.url().startsWith(origin+'/')) return route.continue();
          if(details.blocked_requests.length < 16)details.blocked_requests.push(request.url().slice(0,500));
          return route.abort('blockedbyclient');
        }));
        await bounded(context.routeWebSocket('**/*', socket=>{
          details.blocked_websockets=Math.min(1000,details.blocked_websockets+1); return socket.close();
        }));
        await bounded(context.tracing.start({screenshots:true,snapshots:true,sources:false}));
        page=await bounded(context.newPage()); video=page.video();
        page.on('crash',()=>{crashed=true;});
        page.on('pageerror',error=>{scriptError=String(error.message).slice(0,1000);});
        // Module-resolution and CSP failures may only reach the console. They
        // cannot qualify a missing feature as a completed behavioral failure.
        page.on('console',message=>{if(message.type()==='error')scriptError=String(message.text()).slice(0,1000);});
        page.on('popup',popup=>{crashed=true;popup.close().catch(()=>{});});
        page.setDefaultTimeout(LIMITS.actionMs);
        page.setDefaultNavigationTimeout(LIMITS.actionMs);
        result=await runTest(page,test,origin);
        await bounded(page.screenshot({path:path.join(output,prefix+'.png'),timeout:LIMITS.actionMs}));
      } catch (error) {
        result={id:test.id,status:'infrastructure_failed',error:String(error.message).slice(0,1000)};
      } finally {
        try {
          requireThat(context && video, 'missing browser media');
          await bounded(context.tracing.stop({path:path.join(output,prefix+'.zip')}));
          await bounded(context.close());
          await bounded(rename(await bounded(video.path()),path.join(output,prefix+'.webm')));
          // Playwright's now-empty per-context video directory is not exported.
          const {rmdir}=await import('node:fs/promises');
          await rmdir(path.join(output,prefix+'-video'));
        } catch(error) {
          result={id:test.id,status:'infrastructure_failed',error:[result?.error,
            'media/cleanup: '+String(error.message).slice(0,1000)].filter(Boolean).join('; ').slice(0,2000)};
          if(context) await bounded(context.close()).catch(()=>{});
        }
      }
      if (scriptError !== null) result={id:test.id,status:'infrastructure_failed',error:[result?.error,
        'renderer script error: '+scriptError].filter(Boolean).join('; ').slice(0,2000)};
      details.tests.push(result);
      checks.tests.push({id:test.id,status:result.status});
      // Continue the closed test list even after an earlier failure. Fresh
      // contexts isolate tests; no subset or suite-provided branching exists.
    }
    closing=true; await bounded(browser.close()); browser=null;
    await bounded(new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()))); server=null;
    requireThat(!crashed && checks.tests.every(test=>['passed','assertion_failed'].includes(test.status)), 'browser/test infrastructure failure');
    // Media must be present and nonempty for EVERY test before completion.
    for (let i=1;i<=suite.tests.length;i++) for (const extension of ['png','zip','webm']) {
      const stat=await lstat(path.join(output,`test-${String(i).padStart(2,'0')}.${extension}`));
      requireThat(stat.isFile() && stat.size > 0 && stat.size <= LIMITS.fileBytes, 'missing/oversized media');
    }
    checks.completed=true; checks.infrastructure_failed=false;
    details.status=checks.tests.some(test=>test.status === 'assertion_failed')?'assertion_failed':'completed';
  } catch(error) { details.errors.push(String(error.message).slice(0,1000)); }
  finally {
    if(browser) { closing=true; await bounded(browser.close()).catch(error=>details.errors.push(String(error.message))); }
    if(server) await bounded(new Promise(resolve=>server.close(resolve))).catch(error=>details.errors.push(String(error.message)));
    saveSync();
  }
  try { await writeFile(path.join(output,'output-manifest.json'),canonical(await manifest(output)),{flag:'wx'}); }
  catch(error) {
    checks.completed=false; checks.infrastructure_failed=true; details.status='infrastructure_failed';
    details.errors.push('manifest: '+String(error.message)); saveSync();
  }
  clearTimeout(watchdog);
  return {checks,details};
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  // Fixed mount layout: do not expose an arbitrary candidate-selected driver,
  // Playwright package, path, port, or launch arguments.
  try {
    const chromium={launch:async options=>{
      requireThat(process.getuid() === 1000 && process.getgid() === 1000, 'runtime UID/GID1000 required');
      const pkg=JSON.parse(await readFile('/opt/checker/node_modules/playwright/package.json','utf8'));
      requireThat(pkg.version === '1.64.0', 'admitted Playwright version');
      return (await import('/opt/checker/node_modules/playwright/index.mjs')).chromium.launch(options);
    }};
    const {checks,details}=await runBrowser({inputRoot:'/workspace/inputs',output:'/workspace/artifacts',chromium});
    process.exitCode=checks.infrastructure_failed?2:details.status === 'assertion_failed'?1:0;
  } catch(error) { process.stderr.write(String(error.message)+'\n'); process.exitCode=2; }
}
