// Lightweight host controls. No browser/dependencies or candidate JS is loaded.
import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {canonical, parseSuite, validateSuite, LIMITS, sha, selector} from './suite-contract.mjs';
import {bounded, runTest, runBrowser as actualRunBrowser, fixtureHandler, readAssets} from './browser-driver.mjs';

// This laptop sandbox denies listen(2). Socket-free lifecycle tests exercise the
// real interpreter using a small server double; Zed browser controls bind HTTP.
function fakeServer() {
  const server=new EventEmitter();
  Object.assign(server,{listen:(_port,_host,resolve)=>resolve(),address:()=>({port:4173}),close:resolve=>resolve()});
  return server;
}
const runBrowser=options=>actualRunBrowser({...options,serverFactory:fakeServer});

const suite=()=>({schema:'dsmack-bounty-browser-suite/1',tests:[{id:'a-test',steps:[
  {op:'navigate',path:'/apps/board/'},{op:'assert_count',selector:'[data-testid="search"]',value:1}]}]});
const bytes=()=>Buffer.from(canonical(suite()));
const response=()=>({status:()=>200});
function fakePage({count=1, readError=false, crash=false, scriptError=false, consoleError=false, actionError=false}={}) {
  const page=new EventEmitter();
  Object.assign(page,{
    goto:async()=>{if(crash)page.emit('crash');if(scriptError)page.emit('pageerror',new Error('syntax error'));if(consoleError)page.emit('console',{type:()=> 'error',text:()=> 'module resolution error'});return response();},
    reload:async()=>response(),
    locator:()=>({count:async()=>{if(readError)throw new Error('renderer disconnected');return count;},
      click:async()=>{if(actionError)throw new Error('action timeout');},fill:async()=>{},
      textContent:async()=>'exact',inputValue:async()=>'value',getAttribute:async()=>'1',isVisible:async()=>true}),
    setDefaultTimeout:()=>{},setDefaultNavigationTimeout:()=>{},
    screenshot:async({path:file})=>writeFile(file,'png'),close:async()=>{},
  });
  return page;
}
function fakeChromium(options={}) {
  let contexts=0, stopped=0, browserClosed=false;
  const browser=new EventEmitter();
  browser.newContext=async config=>{
    contexts++;
    const page=fakePage(options);
    const media=path.join(config.recordVideo.dir,'video.webm');
    await mkdir(config.recordVideo.dir);
    page.video=()=>({path:async()=>media});
    return {
      route:async(_pattern, callback)=>{options.routes?.push(callback);},
      routeWebSocket:async(_pattern, callback)=>{options.websocketRoutes?.push(callback);},
      newPage:async()=>page,
      tracing:{start:async()=>{},stop:async({path:file})=>{stopped++;if(options.traceError)throw new Error('trace missing');await writeFile(file,'zip');}},
      close:async()=>{if(options.contextCloseError)throw new Error('context cleanup failed');if(!options.noVideo)await writeFile(media,'webm');},
    };
  };
  browser.close=async()=>{browserClosed=true;if(options.browserCloseError)throw new Error('browser close failed');browser.emit('disconnected');};
  return {launch:async config=>{assert.equal(config.chromiumSandbox,true);if(options.startError)throw new Error('startup failed');return browser;},
    state:()=>({contexts,stopped,browserClosed})};
}
async function temporary(fn) {
  const directory=await mkdtemp(path.join(os.tmpdir(),'bounty-driver-test-'));
  try { return await fn(directory); } finally { await rm(directory,{recursive:true,force:true}); }
}

test('canonical format and CSS subset reject executable, remote and ambiguous input',()=>{
  assert.deepEqual(parseSuite(bytes()),suite());
  for(const css of ['[data-testid="column-todo"] [data-testid="card"] [data-action="right"]','h2 > span','.a#b[data-ready="true"]','*'])selector(css);
  for(const css of ['text=hello','css=body','body >> text=foo',':has-text("x")','[a=x]','a,body','[a="x"]\nscript','[a="http://evil"]'])assert.throws(()=>selector(css));
  for(const change of [s=>s.tests.push(s.tests[0]),s=>s.tests[0].steps.push({op:'eval',code:'process.exit()'}),
    s=>s.tests[0].steps[0].path='https://evil.invalid/',s=>s.tests[0].skip=true,
    s=>s.tests[0].steps[1].value=true,s=>s.tests[0].steps[1].value=1.5,
    s=>s.tests[0].steps=[{op:'navigate',path:'/apps/board/'},{op:'reload'}],
    s=>s.tests=Array.from({length:17},(_,i)=>({id:`a-${i}`,steps:s.tests[0].steps}))]) {
    const value=suite();change(value);assert.throws(()=>validateSuite(value));
  }
  assert.throws(()=>parseSuite(Buffer.from(' '+canonical(suite()))));
  assert.throws(()=>parseSuite(Buffer.from('{"schema":"x",'+canonical(suite()).slice(1))));
  assert.throws(()=>parseSuite(Buffer.from([0xff])));
  assert.throws(()=>parseSuite(Buffer.alloc(LIMITS.suiteBytes+1)));
});

test('only completed assertion mismatch is a behavioral failure',async()=>{
  const definition=suite().tests[0];
  assert.equal((await runTest(fakePage(),definition,'http://local',0)).status,'passed');
  assert.equal((await runTest(fakePage({count:0}),definition,'http://local',0)).status,'assertion_failed');
  assert.equal((await runTest(fakePage({readError:true}),definition,'http://local',0)).status,'infrastructure_failed');
  const action={id:'action',steps:[{op:'fill',selector:'input',value:'x'}]};
  assert.equal((await runTest(fakePage({count:0}),action,'http://local',0)).status,'infrastructure_failed');
  assert.equal((await runTest(fakePage({actionError:true}),{id:'click',steps:[{op:'click',selector:'button'}]},'http://local',0)).status,'infrastructure_failed');
  for(const step of [{op:'assert_text',selector:'p',value:'exact'},
    {op:'assert_value',selector:'input',value:'value'},{op:'assert_attribute',selector:'p',name:'data-x',value:'1'},
    {op:'assert_visible',selector:'p',value:true}]) {
    assert.equal((await runTest(fakePage(),{id:'read',steps:[step]},'http://local',0)).status,'passed');
  }
  await assert.rejects(bounded(new Promise(()=>{}),5),/infrastructure/);
});

test('fresh contexts, all IDs, exact digest, original media and manifest',async()=>temporary(async root=>{
  const value=suite();value.tests.push({...value.tests[0],id:'b-test'});
  const suiteBytes=Buffer.from(canonical(value)), chromium=fakeChromium();
  const output=path.join(root,'output');
  const {checks,details}=await runBrowser({suiteBytes,assets:new Map(),output,chromium});
  assert.deepEqual(checks,{schema:'dsmack-bounty-ci-checks/1',browser_started:true,completed:true,
    infrastructure_failed:false,tests:[{id:'a-test',status:'passed'},{id:'b-test',status:'passed'}],suite_sha256:sha(suiteBytes)});
  assert.equal(details.status,'completed');
  assert.deepEqual(chromium.state(),{contexts:2,stopped:2,browserClosed:true});
  const manifest=JSON.parse(await readFile(path.join(output,'output-manifest.json')));
  assert.deepEqual(manifest.files.map(f=>f.name),(await readdir(output)).filter(name=>name!=='output-manifest.json').sort());
  for(const row of manifest.files) { const raw=await readFile(path.join(output,row.name));assert.equal(row.sha256,sha(raw));assert.equal(row.size,raw.length); }
}));

test('a behavioral failure runs remaining IDs and retains complete media',async()=>temporary(async root=>{
  const value=suite();value.tests.push({...value.tests[0],id:'z-test'});
  const result=await runBrowser({suiteBytes:Buffer.from(canonical(value)),assets:new Map(),output:path.join(root,'out'),chromium:fakeChromium({count:0})});
  assert.equal(result.checks.completed,true);
  assert.equal(result.checks.infrastructure_failed,false);
  assert.deepEqual(result.checks.tests.map(t=>t.id),['a-test','z-test']);
  assert.ok(result.checks.tests.every(t=>t.status==='assertion_failed'));
  assert.equal(result.details.status,'assertion_failed');
}));

test('console-only script failure cannot count as behavioral absence',async()=>temporary(async root=>{
  const {checks,details}=await runBrowser({suiteBytes:bytes(),assets:new Map(),output:path.join(root,'out'),chromium:fakeChromium({count:0,consoleError:true})});
  assert.equal(checks.completed,false);assert.equal(checks.infrastructure_failed,true);
  assert.equal(checks.tests[0].status,'infrastructure_failed');
  assert.match(details.tests[0].error,/module resolution error/);
}));

test('startup, renderer crash/script error, read error, missing media and cleanup refuse completion',async()=>{
  for(const options of [{startError:true},{crash:true},{scriptError:true},{readError:true},{noVideo:true},{traceError:true},
    {contextCloseError:true},{browserCloseError:true}])await temporary(async root=>{
    const {checks,details}=await runBrowser({suiteBytes:bytes(),assets:new Map(),output:path.join(root,'out'),chromium:fakeChromium(options)});
    assert.equal(checks.completed,false,JSON.stringify(options));
    assert.equal(checks.infrastructure_failed,true);
    assert.equal(details.status,'infrastructure_failed');
    assert.ok(details.errors.length);
  });
});

test('invalid suite and absent input keep explicit infrastructure checks',async()=>temporary(async root=>{
  for(const options of [{suiteBytes:Buffer.from('{}'),assets:new Map()},{inputRoot:root}]) {
    const output=path.join(root,options.inputRoot?'missing':'invalid');
    const {checks}=await runBrowser({...options,output,chromium:fakeChromium()});
    assert.equal(checks.completed,false);assert.equal(checks.browser_started,false);
    assert.equal(checks.infrastructure_failed,true);
    assert.deepEqual(JSON.parse(await readFile(path.join(output,'checks.json'))),checks);
  }
}));

test('action infrastructure failure cannot skip a later valid test ID',async()=>temporary(async root=>{
  const value={schema:'dsmack-bounty-browser-suite/1',tests:[
    {id:'a-action',steps:[{op:'navigate',path:'/apps/board/'},{op:'click',selector:'button'},{op:'assert_count',selector:'p',value:0}]},
    {id:'z-assert',steps:[{op:'navigate',path:'/apps/board/'},{op:'assert_count',selector:'p',value:0}]}]};
  const {checks}=await runBrowser({suiteBytes:Buffer.from(canonical(value)),assets:new Map(),output:path.join(root,'out'),chromium:fakeChromium({count:0})});
  assert.equal(checks.completed,false);assert.equal(checks.infrastructure_failed,true);
  assert.deepEqual(checks.tests,[{id:'a-action',status:'infrastructure_failed'},{id:'z-assert',status:'passed'}]);
}));

test('asset snapshot rejects symlinks/oversize; output reuse preserves originals',async()=>temporary(async root=>{
  const input=path.join(root,'inputs');await mkdir(input);
  for(const name of ['board-index.html','board-logic.js','board-ui.js'])await writeFile(path.join(input,name),'unexecuted source');
  assert.equal((await readAssets(input)).size,4);
  await rm(path.join(input,'board-ui.js'));
  await symlink(path.join(input,'board-logic.js'),path.join(input,'board-ui.js'));
  await assert.rejects(readAssets(input),/asset type/);
  await rm(path.join(input,'board-ui.js'));await writeFile(path.join(input,'board-ui.js'),Buffer.alloc(1024*1024+1));
  await assert.rejects(readAssets(input),/asset type/);
  const output=path.join(root,'out');await mkdir(output);await writeFile(path.join(output,'checks.json'),'original');
  await assert.rejects(runBrowser({suiteBytes:bytes(),assets:new Map(),output,chromium:fakeChromium()}),/empty/);
  assert.equal(await readFile(path.join(output,'checks.json'),'utf8'),'original');
}));

test('request gate blocks remote URLs, other fixtures, methods, queries and websockets',async()=>temporary(async root=>{
  const routes=[],websocketRoutes=[];
  await runBrowser({suiteBytes:bytes(),assets:new Map([['/apps/board/',{}]]),output:path.join(root,'out'),chromium:fakeChromium({routes,websocketRoutes})});
  for(const [url,method,expected='abort'] of [['https://remote.invalid/apps/board/','GET'],['http://127.0.0.1:1/apps/board/','GET'],
    ['http://127.0.0.1:4173/apps/board/?x','GET'],['file:///etc/passwd','GET'],['ws://remote.invalid/','GET'],
    ['http://127.0.0.1:4173/apps/board/','POST'],['http://127.0.0.1:4173/apps/board/','GET','continue']]) {
    let action;
    await routes[0]({request:()=>({url:()=>url,method:()=>method}),continue:()=>{action='continue';},abort:()=>{action='abort';}});
    assert.equal(action,expected);
  }
  let closed=false;websocketRoutes[0]({close:()=>{closed=true;}});assert.ok(closed);
}));

test('fixture handler serves only exact in-memory admitted paths',()=>{
  const handler=fixtureHandler(new Map([['/apps/board/',{type:'text/html',bytes:Buffer.from('fixture')}]]));
  for(const [url,method,status] of [['/apps/board/','GET',200],['/etc/passwd','GET',404],
    ['/apps/board/?x','GET',404],['/apps/board/ui.js','GET',404],['/apps/board/%2e%2e/','GET',404],['/apps/board/','POST',404]]) {
    let code,body;
    handler({url,method},{writeHead:value=>{code=value;},end:value=>{body=value;}});
    assert.equal(code,status);if(status===200)assert.equal(body.toString(),'fixture');
  }
});

test('global deadline overwrites partial state and exits as infrastructure failure',async()=>temporary(async root=>{
  const output=path.join(root,'out');
  const code=`import {runBrowser} from ${JSON.stringify(new URL('./browser-driver.mjs',import.meta.url).href)};
    await runBrowser({suiteBytes:Buffer.from(${JSON.stringify(canonical(suite()))}),assets:new Map(),output:${JSON.stringify(output)},
      serverFactory:()=>({once:()=>{},listen:(_p,_h,resolve)=>resolve(),address:()=>({port:4173}),close:resolve=>resolve()}),
      chromium:{launch:()=>new Promise(()=>{})},wallMs:30});`;
  const env={...process.env};delete env.NODE_TEST_CONTEXT;
  const child=spawnSync(process.execPath,['--input-type=module','-e',code],{timeout:3000,env});
  assert.equal(child.status,2,child.stderr.toString());
  const checks=JSON.parse(await readFile(path.join(output,'checks.json')));
  assert.equal(checks.completed,false);assert.equal(checks.infrastructure_failed,true);
  assert.match((await readFile(path.join(output,'driver-details.json'))).toString(),/global deadline/);
}));
