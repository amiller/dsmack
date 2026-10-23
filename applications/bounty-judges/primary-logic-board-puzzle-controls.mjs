// Run against actual baseline Chromium pages supplied by the harness owner.
// This tests trusted Node comparisons; candidate-mutation tests additionally
// require the caller to serve the named mutated source to a fresh context.
import assert from 'node:assert/strict';
import {runLogic as board,CASE_IDS as boardCases} from './primary-logic-board.mjs';
import {runLogic as puzzle,CASE_IDS as puzzleCases} from './primary-logic-puzzle.mjs';
export async function runObservationControls(withPage){
 for(const [app,run,ids] of [['board',board,boardCases],['puzzle',puzzle,puzzleCases]])
  await withPage(async page=>assert.deepEqual(await run(page),[...ids]),app);
 const controls=[['undefined-is-not-null',board,r=>{r[7][2]=null;}],['missing-required-throw',board,r=>{r[12][0]={threw:false};}],['reference-identity',puzzle,r=>{r[5][0]=false;}],['undo-count',puzzle,r=>{r[16][0][0][2]=999;}],['known-solution',puzzle,r=>{r[20][1]=false;}]];
 for(const [name,run,change] of controls)await withPage(async page=>{
  const observing={goto:(...args)=>page.goto(...args),evaluate:async(...args)=>{const value=await page.evaluate(...args);change(value);return value;}};
  await assert.rejects(()=>run(observing),undefined,name);
 },name);
 return controls.map(c=>c[0]);
}
export const CANDIDATE_MUTATIONS=Object.freeze({
 board:{before:'next.nextId++',after:'++next.nextId',reason:'sequential IDs and nextId must retain original semantics'},
 puzzle:{before:'return state',after:'return {...state}',all:true,reason:'blocked movement and initial undo must preserve reference identity'},
});
