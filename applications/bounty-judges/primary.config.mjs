import {defineConfig} from '/opt/checker/node_modules/@playwright/test/index.mjs';
if(process.cwd()!=='/workspace/state/primary-run')throw Error('fixed primary child cwd');
export default defineConfig({
  testDir:'/workspace/state/primary-run/primary-tests',outputDir:'/workspace/state/primary-run/primary-results',
  testMatch:/.*\.spec\.mjs$/,workers:1,retries:0,repeatEach:1,fullyParallel:false,
  timeout:25000,globalTimeout:480000,forbidOnly:true,
  reporter:[['/opt/bounty-judges/primary-reporter.mjs']],
  use:{baseURL:'http://127.0.0.1:4173',headless:true,serviceWorkers:'block',
    launchOptions:{chromiumSandbox:true},viewport:{width:1000,height:720},
    video:'on',trace:'on',screenshot:'on',actionTimeout:5000,navigationTimeout:5000},
});
