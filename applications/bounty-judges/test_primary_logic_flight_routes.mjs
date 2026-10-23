// No candidate module executes in Node. Actual calculations qualify in browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {CASE_IDS as FLIGHT,runLogic as flight} from './primary-logic-flight.mjs';
import {CASE_IDS as ROUTES,runLogic as routes} from './primary-logic-routes.mjs';
const original=process.env.DSMACK_PRIMARY_ORIGINAL_ROOT || new URL('./primary-original/',import.meta.url);
const originalFile=(app)=>typeof original==='string'?original+`/apps/${app}/test/logic.test.js`:new URL(`apps/${app}/test/logic.test.js`,original);
for(const [app,ids,run] of [['flight',FLIGHT,flight],['routes',ROUTES,routes]]){
  test(app+' exact original unexpanded test identity inventory',async()=>{
    const raw=await readFile(originalFile(app),'utf8');
    const names=[...raw.matchAll(/^test\('([^']+)',/gm)].map(match=>match[1]);
    assert.deepEqual(ids,names);assert.ok(Object.isFrozen(ids));
  });
}
test('flight Node assertion side refuses corrupted renderer observation',async()=>{
  const page={evaluate:async()=>({rngA:[0],rngB:[1]})};
  await assert.rejects(flight(page),assert.AssertionError);
});
test('flight never accepts renderer-authored pass count as authority',async()=>{
  await assert.rejects(flight({evaluate:async()=>({passed:15,case_ids:FLIGHT})}));
});
