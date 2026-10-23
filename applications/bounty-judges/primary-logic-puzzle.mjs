// Complete original puzzle cases; expected assertions stay in trusted Node.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const levelsRaw=readFileSync(new URL('./primary-original/apps/puzzle/levels.json',import.meta.url));
const source=JSON.parse(readFileSync(new URL('./primary-original/SOURCE.json',import.meta.url)));
const levels=JSON.parse(levelsRaw);
const solutions={'First Push':'rRR','Corner':'DrdLuuullddR','Two Lanes':'lLLLrrrddLLL','Pillar':'rruulDrdLLLrruullDlDRRRurD','Storeroom':'URdrUluLLDDldR','Warehouse':'RurrddddlDRuuuuLLLrdRDrddlLdllURlU'};
export const CASE_IDS=Object.freeze(['parse reads walls, goals, boxes and player','parse handles + and * and ragged rows','parse rejects malformed levels','render round-trips every level','walking moves the player and counts moves','walls block movement and return the same state','moves off the map edge are blocked','pushing moves a box and counts a push','cannot push a box into a wall','cannot push two boxes','cannot push a box off the edge of an open map','move rejects unknown directions','move does not mutate the previous state','win detection','play throws on a blocked move','every level has a recorded solution','undo reverses walks and pushes exactly','undo at the start is a no-op','blocked moves are not recorded in history','interior excludes the empty outside of a level',...levels.map(l=>`level "${l.name}" is won by its known solution`)]);
export async function runLogic(page){
 // Fixed original fixture; never consume candidate-selected levels or solutions.
 const pin=source.files.find(x=>x.path==='apps/puzzle/levels.json');
 assert.ok(pin,'original level fixture pin');assert.equal(createHash('sha256').update(levelsRaw).digest('hex'),pin.sha256);
 await page.goto('/__primary_logic__/');
 const actual=await page.evaluate(async({levels,solutions})=>{
  const clone=globalThis.structuredClone;
  const {parse,move,undo,play,isWon,moves,pushes,render,interior}=await import('/apps/puzzle/logic.js');
  const error=fn=>{try{fn();return {threw:false};}catch(e){return {threw:true,message:typeof e?.message==='string'?e.message:null};}};
  const out=[];const push=value=>out.push(clone(value));
  {const s=parse(['#####','#@$.#','#####']);push([s.w,s.h,s.player,s.boxes,[...s.goals],s.walls.size,moves(s)]);}
  {const s=parse(['####','#+*#','#$ #','###']);push([s.w,s.player,[...s.goals].sort(),s.boxes]);}
  push([error(()=>parse(['#$.#'])),error(()=>parse(['#@@$..#'])),error(()=>parse(['#@$$.#'])),error(()=>parse(['#@x$.#']))]);
  push(levels.map(lv=>render(parse(lv.map))));
  {const s=move(parse(['#####','#@ .#','#$  #','#####']),'r');push([render(s),moves(s),pushes(s)]);}
  {const s=parse(['#####','#@$.#','#####']);push([... 'udl'].map(d=>move(s,d)===s));}
  {const s=parse(['@$.']);push([move(s,'l')===s,move(s,'u')===s]);}
  {const s=move(parse(['######','#@$ .#','######']),'r');push([render(s),pushes(s),s.history]);}
  {const s=parse(['#####','# @$#','#.  #','#####']);push(move(s,'r')===s);}
  {const s=parse(['#######','#@$$..#','#######']);push(move(s,'r')===s);}
  {const s=parse(['.@$']);push(move(s,'r')===s);}
  push(error(()=>move(parse(['@$.']),'x')));
  {const s=parse(['######','#@$ .#','######']);const before=render(s);play(s,'rr');push([render(s),before,moves(s)]);}
  {const s=parse(['#@$.#']);push([isWon(parse(['#@*#'])),isWon(s),isWon(move(s,'r'))]);}
  push(error(()=>play(parse(['#@$.#']),'l')));
  push(null); // Coverage assertion depends only on fixed original data in Node.
  push(levels.map(lv=>{const states=[parse(lv.map)];for(const c of solutions[lv.name])states.push(move(states.at(-1),c.toLowerCase()));let s=states.at(-1);const rows=[];for(let i=states.length-2;i>=0;i--){s=undo(s);rows.push([render(s),render(states[i]),moves(s)]);}return rows;}));
  {const s=parse(['#@$.#']);push(undo(s)===s);}
  {const s=parse(['#####','#@$.#','#####']);push(moves(move(move(s,'u'),'l')));}
  {const s=parse([' ###','##@#','#$.#','####']);push([...interior(s)].sort((a,b)=>a-b));}
  for(const lv of levels){const sol=solutions[lv.name],s0=parse(lv.map);const initial=isWon(s0),won=play(s0,sol);push([initial,isWon(won),moves(won),pushes(won),won.history.join(''),isWon(undo(won))]);}
  return out;
 },{levels,solutions});
 assert.equal(actual.length,CASE_IDS.length,'complete puzzle observations');
 const eq=(a,b)=>assert.deepEqual(a,b);const throws=(a,re)=>{assert.equal(a.threw,true);assert.equal(typeof a.message,'string');assert.match(a.message,re);};
 eq(actual[0],[5,3,6,[7],[8],12,0]);eq(actual[1],[4,5,[5,6],[6,9]]);
 for(const [i,re] of [/no player/,/more than one player/,/2 boxes but 1 goals/,/bad tile 'x'/].entries())throws(actual[2][i],re);
 eq(actual[3],levels.map(lv=>lv.map.map(r=>r.trimEnd())));
 eq(actual[4],[['#####','# @.#','#$  #','#####'],1,0]);eq(actual[5],[true,true,true]);eq(actual[6],[true,true]);
 eq(actual[7],[['######','# @$.#','######'],1,['R']]);for(const i of [8,9,10])assert.equal(actual[i],true);
 throws(actual[11],/bad direction/);eq(actual[12][0],actual[12][1]);assert.equal(actual[12][2],0);eq(actual[13],[true,false,true]);throws(actual[14],/blocked move 'l' at step 0/);
 eq(levels.map(l=>l.name).sort(),Object.keys(solutions).sort());
 assert.equal(actual[16].length,levels.length);
 for(let l=0;l<levels.length;l++){const count=solutions[levels[l].name].length;assert.equal(actual[16][l].length,count);for(let j=0;j<count;j++){const row=actual[16][l][j];eq(row[0],row[1]);assert.equal(row[2],count-1-j);}}
 assert.equal(actual[17],true);assert.equal(actual[18],0);eq(actual[19],[6,9,10]);
 for(let l=0;l<levels.length;l++){const sol=solutions[levels[l].name];assert.ok(sol,`no solution recorded for ${levels[l].name}`);eq(actual[20+l],[false,true,sol.length,[...sol].filter(c=>c===c.toUpperCase()).length,sol,false]);}
 return [...CASE_IDS];
}
