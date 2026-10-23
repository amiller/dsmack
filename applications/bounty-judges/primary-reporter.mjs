import {writeFileSync} from 'node:fs';
import path from 'node:path';
import {canonical} from './suite-contract.mjs';
if(process.cwd()!=='/workspace/state/primary-run')throw Error('fixed primary child cwd');
// Only the trusted Playwright test-runner process writes this report. stdout
// and browser-produced pass flags are never parsed as completion authority.
export default class PrimaryReporter {
  constructor(){this.tests=[];this.errors=[];this.discovered=[];}
  onBegin(_config,suite){this.discovered=suite.allTests().map(test=>({file:path.basename(test.location.file),title:test.title}));}
  onError(error){this.errors.push(String(error.message).slice(0,2000));}
  onTestEnd(test,result){
    this.tests.push({file:path.basename(test.location.file),title:test.title,status:result.status,
      expected_status:test.expectedStatus,retry:result.retry,
      annotations:test.annotations.map(a=>({type:a.type,description:a.description||''})),
      errors:result.errors.map(e=>String(e.message).slice(0,2000)),
      attachments:result.attachments.filter(a=>a.path).map(a=>({name:a.name,path:a.path}))});
  }
  onEnd(result){writeFileSync('/workspace/state/primary-run/primary-raw-report.json',canonical({schema:'dsmack-bounty-primary-raw/1',
    status:result.status,discovered:this.discovered,tests:this.tests,errors:this.errors}));}
}
