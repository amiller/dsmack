// Four complete original suite aggregates. Candidate code runs only in Chromium;
// each helper's expected comparisons are owned by trusted Node assertions.
import assert from 'node:assert/strict';
import {test} from '/opt/bounty-judges/primary-fixtures.mjs';
import {verifyLogicCoverage} from '/opt/bounty-judges/primary-logic-admission.mjs';
import * as board from '/opt/bounty-judges/primary-logic-board.mjs';
import * as flight from '/opt/bounty-judges/primary-logic-flight.mjs';
import * as puzzle from '/opt/bounty-judges/primary-logic-puzzle.mjs';
import * as routes from '/opt/bounty-judges/primary-logic-routes.mjs';
for(const [app,helper] of Object.entries({board,flight,puzzle,routes})){
 test('fixed-logic-'+app,async({page},testInfo)=>{
  let group;
  try{group=(await verifyLogicCoverage('/opt/bounty-judges')).groups[app];
   assert.deepEqual([...helper.CASE_IDS],group.required_case_ids);
  }catch(error){testInfo.annotations.push({type:'primary-infrastructure',description:'unadmitted original logic source/case closure'});throw error;}
  await page.goto('/__primary_logic__/');
  // Returning IDs alone is never authority: runLogic executes every original
  // observed-vector comparison in trusted Node before returning these IDs.
  assert.deepEqual(await helper.runLogic(page),group.required_case_ids);
 });
}
