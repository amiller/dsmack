// Source-coverage admission only. Actual selected-image/native qualification is separate.
import {readFile,lstat} from 'node:fs/promises';
import path from 'node:path';
import {sha,requireThat} from './suite-contract.mjs';
export const LOGIC_COUNTS=Object.freeze({board:27,flight:15,puzzle:26,routes:12});
async function regular(file,cap){const s=await lstat(file);requireThat(s.isFile()&&!s.isSymbolicLink()&&s.size<=cap,'logic source type/size');const b=await readFile(file);requireThat(b.length===s.size,'logic source size changed');return b;}
export async function verifyLogicCoverage(source){
 const coverage=JSON.parse(await regular(path.join(source,'primary-logic-coverage.json'),262144));
 requireThat(coverage.schema==='dsmack-bounty-primary-logic-coverage/1'&&coverage.commit==='5c76d40e77db1f4864dabd4b9398d02589cff330','logic coverage source');
 requireThat(JSON.stringify(Object.keys(coverage.groups).sort())===JSON.stringify(Object.keys(LOGIC_COUNTS).sort()),'closed four logic aggregates');
 for(const [app,count] of Object.entries(LOGIC_COUNTS)){
  const g=coverage.groups[app],name='primary-logic-'+app+'.mjs';
  requireThat(g.admitted===true&&g.module===name&&/^[a-f0-9]{64}$/.test(g.module_sha256),'complete reviewed logic module required');
  requireThat(g.original_source==='apps/'+app+'/test/logic.test.js','original logic source path');
  requireThat(Array.isArray(g.required_case_ids)&&g.required_case_ids.length===count&&new Set(g.required_case_ids).size===count&&g.required_case_ids.every(x=>typeof x==='string'&&x.length>0&&x.length<=240),'complete original logic cases');
  const rows=g.renderer_assertion_correspondence;
  requireThat(Array.isArray(rows)&&rows.length===count&&rows.every((row,i)=>row.id===g.required_case_ids[i]&&row.module===name&&row.original_source===g.original_source),'complete assertion correspondence');
  requireThat(sha(await regular(path.join(source,name),65536))===g.module_sha256,'reviewed logic module source pin');
 }
 return coverage;
}
