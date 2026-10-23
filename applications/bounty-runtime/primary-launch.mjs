// Fixed application bridge to selected primary harness; no candidate Node imports.
import {readFile} from 'node:fs/promises';
import {runPrimary} from '/opt/bounty-judges/primary-driver.mjs';
if(process.argv.length!==3||!/^[0-9a-f]{64}$/.test(process.argv[2])||process.getuid()!==1000||process.getgid()!==1000)throw Error('fixed primary invocation');
const pkg=JSON.parse(await readFile('/opt/checker/node_modules/playwright/package.json','utf8'));
if(pkg.version!=='1.64.0')throw Error('selected Playwright version');
const {details}=await runPrimary({candidate:'/workspace/state/candidate-projection',expectedTree:process.argv[2],state:'/workspace/state/primary-run',output:'/workspace/artifacts'});
process.exitCode=details.status==='completed'?0:details.status==='assertion_failed'?1:2;
