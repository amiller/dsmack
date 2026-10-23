// Original suite: primary-original/apps/board/test/logic.test.js.
// Candidate executes only in the renderer. All expected comparisons are Node-owned.
import assert from 'node:assert/strict';
export const CASE_IDS=Object.freeze([
'add appends cards with sequential ids and trimmed text','add rejects empty text and unknown columns','applyAction does not mutate its input','edit changes text in place and keeps position','delete removes the card and never reuses its id','move appends to target column by default','move with index reorders within and across columns','neighbour steps across columns and stops at the edges','findCard reports column and index','unknown action types throw','export/import round-trips through JSON','validate accepts a well-formed board',
...['null','array','missing nextId','zero nextId','fractional nextId','missing column','extra column','column not array','card missing text','card extra field','empty text','non-string text','malformed id','id not below nextId','duplicate id'].map(x=>'validate rejects: '+x)]);
export async function runLogic(page){
 await page.goto('/__primary_logic__/');
 const actual=await page.evaluate(async()=>{
  const clone=globalThis.structuredClone;
  const {applyAction,emptyBoard,validate,neighbour,findCard}=await import('/apps/board/logic.js');
  const run=(actions,b=emptyBoard())=>actions.reduce(applyAction,b);
  const texts=(b,c)=>b.columns[c].map(x=>x.text);
  const error=fn=>{try{fn();return {threw:false};}catch(e){return {threw:true,message:typeof e?.message==='string'?e.message:null};}};
  const out=[];const push=value=>out.push(clone(value));
  {const b=run([{type:'add',column:'todo',text:' a '},{type:'add',column:'todo',text:'b'},{type:'add',column:'done',text:'c'}]);push([b.columns.todo,b.columns.done,b.nextId]);}
  push([error(()=>run([{type:'add',column:'todo',text:'   '}])),error(()=>run([{type:'add',column:'later',text:'x'}]))]);
  {const b=run([{type:'add',column:'todo',text:'a'}]);const before=clone(b);run([{type:'edit',id:'c1',text:'z'},{type:'move',id:'c1',to:'done'},{type:'add',column:'todo',text:'q'}],b);push([b,before]);}
  {const b=run([{type:'add',column:'todo',text:'a'},{type:'add',column:'todo',text:'b'},{type:'edit',id:'c1',text:'A'}]);push([texts(b,'todo'),error(()=>applyAction(b,{type:'edit',id:'c9',text:'x'})),error(()=>applyAction(b,{type:'edit',id:'c1',text:''}))]);}
  {const b=run([{type:'add',column:'todo',text:'a'},{type:'delete',id:'c1'},{type:'add',column:'todo',text:'b'}]);push([b.columns.todo,error(()=>applyAction(b,{type:'delete',id:'c1'}))]);}
  {const b=run([{type:'add',column:'todo',text:'a'},{type:'add',column:'doing',text:'b'},{type:'move',id:'c1',to:'doing'}]);push([texts(b,'todo'),texts(b,'doing')]);}
  {const b=run(['a','b','c'].map(text=>({type:'add',column:'todo',text})));push([texts(applyAction(b,{type:'move',id:'c3',to:'todo',index:0}),'todo'),texts(applyAction(b,{type:'move',id:'c1',to:'todo',index:2}),'todo'),texts(run([{type:'add',column:'done',text:'x'},{type:'move',id:'c2',to:'done',index:0}],b),'done'),error(()=>applyAction(b,{type:'move',id:'c1',to:'todo',index:3})),error(()=>applyAction(b,{type:'move',id:'c1',to:'nowhere'}))]);}
  push([neighbour('todo',1),neighbour('done',-1),neighbour('todo',-1),neighbour('done',1)]);
  {const b=run([{type:'add',column:'doing',text:'a'},{type:'add',column:'doing',text:'b'}]);push(findCard(b,'c2'));}
  push(error(()=>applyAction(emptyBoard(),{type:'archive'})));
  {const b=run([{type:'add',column:'todo',text:'a'},{type:'add',column:'done',text:'b'},{type:'move',id:'c1',to:'doing'}]);const imported=applyAction(emptyBoard(),{type:'import',board:JSON.parse(JSON.stringify(b))});push([imported,b,applyAction(imported,{type:'add',column:'todo',text:'c'}).columns.todo[0].id]);}
  const valid=()=>({nextId:3,columns:{todo:[{id:'c1',text:'a'}],doing:[],done:[{id:'c2',text:'b'}]}});
  push([validate(valid()),valid(),validate(emptyBoard()),emptyBoard()]);
  const invalid=[null,[],(({nextId,...b})=>b)(valid()),{...valid(),nextId:0},{...valid(),nextId:2.5},{nextId:3,columns:{todo:[],doing:[]}},{nextId:3,columns:{...valid().columns,later:[]}},{nextId:3,columns:{...valid().columns,doing:{}}},{nextId:3,columns:{...valid().columns,doing:[{id:'c9'}]}},{nextId:3,columns:{...valid().columns,todo:[{id:'c1',text:'a',due:1}]}},{nextId:3,columns:{...valid().columns,todo:[{id:'c1',text:' '}]}},{nextId:3,columns:{...valid().columns,todo:[{id:'c1',text:5}]}},{nextId:3,columns:{...valid().columns,todo:[{id:'x1',text:'a'}]}},{...valid(),nextId:2},{nextId:3,columns:{...valid().columns,doing:[{id:'c1',text:'dup'}]}}];
  for(const b of invalid)push([error(()=>validate(b)),error(()=>applyAction(emptyBoard(),{type:'import',board:b}))]);
  return out;
 });
 assert.equal(actual.length,CASE_IDS.length,'complete board observations');
 const eq=(a,b)=>assert.deepEqual(a,b);const throws=(a,re)=>{assert.equal(a.threw,true);assert.equal(typeof a.message,'string');assert.match(a.message,re);};
 eq(actual[0],[[{id:'c1',text:'a'},{id:'c2',text:'b'}],[{id:'c3',text:'c'}],4]);
 throws(actual[1][0],/non-empty/);throws(actual[1][1],/no column later/);
 eq(actual[2][0],actual[2][1]);
 eq(actual[3][0],['A','b']);throws(actual[3][1],/no card c9/);throws(actual[3][2],/non-empty/);
 eq(actual[4][0],[{id:'c2',text:'b'}]);throws(actual[4][1],/no card c1/);
 eq(actual[5],[[],['b','a']]);
 eq(actual[6][0],['c','a','b']);eq(actual[6][1],['b','c','a']);eq(actual[6][2],['b','x']);throws(actual[6][3],/bad index/);throws(actual[6][4],/no column/);
 eq(actual[7],['doing','doing',undefined,undefined]);
 eq(actual[8],{col:'doing',index:1,card:{id:'c2',text:'b'}});throws(actual[9],/unknown action archive/);
 eq(actual[10][0],actual[10][1]);assert.equal(actual[10][2],'c3');
 eq(actual[11][0],actual[11][1]);eq(actual[11][2],actual[11][3]);
 for(let i=12;i<CASE_IDS.length;i++){throws(actual[i][0],/invalid board/);throws(actual[i][1],/invalid board/);}
 return [...CASE_IDS];
}
