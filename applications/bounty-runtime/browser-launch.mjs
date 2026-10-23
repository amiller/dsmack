// Application-image source; no candidate-selected imports or process arguments.
import {readFile} from 'node:fs/promises';
import {runBrowser} from '/opt/bounty-judges/browser-driver.mjs';
if(process.argv.length!==2 || process.getuid()!==1000 || process.getgid()!==1000)throw Error('fixed UID/argv');
const pkg=JSON.parse(await readFile('/opt/checker/node_modules/playwright/package.json','utf8'));
if(pkg.version!=='1.64.0')throw Error('selected Playwright version');
const chromium=(await import('/opt/checker/node_modules/playwright/index.mjs')).chromium;
const {checks,details}=await runBrowser({inputRoot:'/workspace/state/projection',output:'/workspace/artifacts',chromium});
process.exitCode=checks.infrastructure_failed?2:details.status==='assertion_failed'?1:0;
