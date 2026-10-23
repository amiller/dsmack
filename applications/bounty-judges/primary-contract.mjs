// Closed, fixed primary inventory. Order is the checks.json array order.
import path from 'node:path';
import {canonical,requireThat,keys} from './suite-contract.mjs';
export const BROWSER=Object.freeze([
  {id:'browser-board',file:'board.spec.mjs',source:'board.spec.js',title:'add a card, move it, and it survives reload',sha256:'31a98d86ee00418520c1cca966b2751b9f7c0e1220247cdc5079f18c66e993e3'},
  {id:'browser-flight',file:'flight.spec.mjs',source:'flight.spec.js',title:'flight loads, flies, and responds to throttle',sha256:'f6e59d2ba60f1c180fe0c24c73c05bef7f8335e4d026de3f89c1449aa44200b2'},
  {id:'browser-puzzle',file:'puzzle.spec.mjs',source:'puzzle.spec.js',title:'puzzle loads, solves level 1 with buttons and keys, and undoes',sha256:'c17168c9a4af38e97b8d296b3ec37ec9cbfa80852328b974ad0bf90b50756f41'},
  {id:'browser-routes',file:'routes.spec.mjs',source:'routes.spec.js',title:'routes loads a sample, switches samples and opens a file',sha256:'b34d392f63a25f3d46376784053c6ef8d405107af60392fcf0ddfcd47f9de9e6'},
]);
export const LOGIC=['board','flight','puzzle','routes'].map(app=>({id:'logic-'+app,file:'primary-logic.spec.mjs',title:'fixed-logic-'+app}));
export const FEATURES=['baseline-add-and-reload','search-case-insensitive-all-columns',
  'search-trim-empty-and-view-only-persistence','filtered-move-targets-original-card',
  'logic-filter-ids-no-mutation','export-keeps-unfiltered-board'].map(title=>({id:'feature-'+title,file:'primary-feature.spec.mjs',title}));
export const INVENTORY=Object.freeze([...BROWSER,...LOGIC,...FEATURES]);
export function emptyChecks(){return {schema:'dsmack-bounty-primary-checks/1',
  fixed_browser_baselines:BROWSER.map(()=>false),fixed_logic_baselines:LOGIC.map(()=>false),feature_checks:FEATURES.map(()=>false)};}
const identity=test=>test.file+'\0'+test.title;
export function admitReport(bytes,{captureInfrastructure=false}={}){
  requireThat(bytes.length>0 && bytes.length<=1024*1024,'primary report byte bound');
  const raw=new TextDecoder('utf8',{fatal:true}).decode(bytes),report=JSON.parse(raw);
  requireThat(canonical(report)===raw,'canonical primary report');
  keys(report,['schema','status','discovered','tests','errors']);
  requireThat(report.schema==='dsmack-bounty-primary-raw/1' && ['passed','failed','timedout','interrupted'].includes(report.status),'primary report schema/status');
  requireThat(Array.isArray(report.errors) && report.errors.length===0,'runner global errors');
  requireThat(Array.isArray(report.discovered) && Array.isArray(report.tests)
    && report.discovered.length===14 && report.tests.length===14,'closed fourteen tests');
  const expected=INVENTORY.map(identity).sort();
  requireThat(JSON.stringify(report.discovered.map(identity).sort())===JSON.stringify(expected),'closed test discovery');
  requireThat(JSON.stringify(report.tests.map(identity).sort())===JSON.stringify(expected),'closed terminal test membership');
  for(const row of report.tests){
    keys(row,['file','title','status','expected_status','retry','annotations','errors','attachments']);
    requireThat(row.expected_status==='passed' && row.retry===0 && ['passed','failed'].includes(row.status),'no skipped/retried/timed-out tests');
    requireThat(Array.isArray(row.annotations) && row.annotations.every(a=>!['skip','fixme','fail'].includes(a.type)
      && (captureInfrastructure || a.type!=='primary-infrastructure')),'test infrastructure/skip annotation');
    requireThat(Array.isArray(row.errors) && (row.status!=='passed' || row.errors.length===0),'passed test with error');
    requireThat(Array.isArray(row.attachments) && row.attachments.length<=8,'media count');
  }
  const allPassed=report.tests.every(t=>t.status==='passed');
  requireThat(report.status===(allPassed?'passed':'failed'),'runner status agrees with tests');
  return report;
}
export function checksFromReport(report){
  // Call ONLY after admission, media validation and successful owned cleanup.
  const rows=new Map(report.tests.map(row=>[identity(row),row]));
  return {schema:'dsmack-bounty-primary-checks/1',
    fixed_browser_baselines:BROWSER.map(test=>rows.get(identity(test)).status==='passed'),
    fixed_logic_baselines:LOGIC.map(test=>rows.get(identity(test)).status==='passed'),
    feature_checks:FEATURES.map(test=>rows.get(identity(test)).status==='passed')};
}
export function selectedMedia(row,state){
  const output=[];
  for(const [name,extension] of [['screenshot','png'],['trace','zip'],['video','webm']]){
    const matches=row.attachments.filter(a=>a.name===name);
    requireThat(matches.length===1 && typeof matches[0].path==='string','missing/duplicate required '+name);
    const absolute=path.resolve(matches[0].path),root=path.resolve(state,'primary-results')+path.sep;
    requireThat(absolute.startsWith(root),'media outside owned results');
    output.push({source:absolute,name:INVENTORY.find(test=>identity(test)===identity(row)).id+'.'+extension});
  }
  return output;
}
