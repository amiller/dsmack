// Protected deterministic task controllers. Candidate modules run only in Chromium.
import {rename} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {chromium} from '/opt/checker/node_modules/playwright/index.mjs';
const [origin,out,task]=process.argv.slice(2);
const tests=[];let browser,context,page,current='task-profile',outcome='infrastructure_failure';
class Assertion extends Error{}
const need=v=>{if(!v)throw new Assertion('functional assertion');};
const equal=isDeepStrictEqual;
async function wait(fn,functional=true,ms=5000){const end=Date.now()+ms;while(Date.now()<end){if(await fn())return;await new Promise(r=>setTimeout(r,25));}throw functional?new Assertion('functional assertion'):new Error('initialization timeout');}
async function check(id,fn){current=id;await fn();tests.push({id,status:'passed'});}
async function boardUndo(){
 const board=()=>page.getByTestId('board');const button=id=>page.getByTestId(id);
 const cards=col=>page.getByTestId('column-'+col).getByTestId('card');
 const texts=async col=>cards(col).locator('p').allTextContents();
 const card=(col,text)=>cards(col).filter({hasText:text}).first();
 const stored=async fn=>{const before=Number(await board().getAttribute('data-saved')||0);await fn();await wait(async()=>await board().getAttribute('data-saved')===String(before+1));};
 const add=async(col,text)=>{await page.getByTestId('new-'+col).fill(text);await stored(()=>page.getByTestId('add-'+col).click());};
 await check('undo-controls',async()=>{await page.goto(origin+'/apps/board/');await wait(async()=>await board().getAttribute('data-ready')==='true',false);need(await button('undo').count()===1&&await button('redo').count()===1);need(!await button('undo').isEnabled()&&!await button('redo').isEnabled());});
 await check('history-api',async()=>{
  const value=await page.evaluate(async()=>{try{const m=await import('/apps/board/logic.js');if(!['createHistory','record','undo','redo'].every(k=>typeof m[k]==='function'))return null;const h=m.createHistory(m.emptyBoard()),before=JSON.stringify(h);const a=m.record(h,{type:'add',column:'todo',text:'a'}),b=m.record(a,{type:'add',column:'todo',text:'b'}),u=m.undo(b),r=m.redo(u);return {unchanged:JSON.stringify(h)===before,add:a.present.columns.todo.map(c=>c.text),undo:u.present.columns.todo.map(c=>c.text),redo:r.present.columns.todo.map(c=>c.text),distinct:a!==h&&u!==b&&r!==u};}catch{return null;}});
  need(value&&value.unchanged&&value.distinct&&equal(value.add,['a'])&&equal(value.undo,['a'])&&equal(value.redo,['a','b']));
 });
 await check('history-limit',async()=>{
  const value=await page.evaluate(async()=>{try{const m=await import('/apps/board/logic.js');let h=m.createHistory(m.emptyBoard());for(let i=0;i<60;i++)h=m.record(h,{type:'add',column:'todo',text:String(i)});const cap=h.past.length;for(let i=0;i<50;i++)h=m.undo(h);let throws=false;try{m.undo(h);}catch(e){throws=/nothing to undo/i.test(e.message);}return {cap,cards:h.present.columns.todo.length,throws};}catch{return null;}});
  need(value&&value.cap===50&&value.cards===10&&value.throws);
 });
 await check('edit-delete-move',async()=>{
  await add('todo','alpha');await add('todo','beta');await stored(()=>card('todo','alpha').locator('[data-action=right]').click());need(equal(await texts('doing'),['alpha']));
  await stored(()=>button('undo').click());need(equal(await texts('todo'),['alpha','beta']));await stored(()=>button('redo').click());need(equal(await texts('doing'),['alpha']));
  await card('doing','alpha').locator('[data-action=edit]').click();await cards('doing').locator('input').fill('alpha edited');await stored(()=>cards('doing').locator('input').press('Enter'));need(equal(await texts('doing'),['alpha edited']));
  await stored(()=>button('undo').click());need(equal(await texts('doing'),['alpha']));await stored(()=>button('redo').click());need(equal(await texts('doing'),['alpha edited']));
  await stored(()=>card('doing','alpha edited').locator('[data-action=delete]').click());need(await cards('doing').count()===0);await stored(()=>button('undo').click());need(equal(await texts('doing'),['alpha edited']));
  await add('doing','delta');await stored(()=>card('doing','alpha edited').locator('[data-action=down]').click());need(equal(await texts('doing'),['delta','alpha edited']));await stored(()=>button('undo').click());need(equal(await texts('doing'),['alpha edited','delta']));await stored(()=>button('redo').click());need(equal(await texts('doing'),['delta','alpha edited']));
 });
 await check('redo-branch',async()=>{await stored(()=>button('undo').click());need(await button('redo').isEnabled());await add('todo','charlie');need(!await button('redo').isEnabled()&&await button('undo').isEnabled());
  const result=await page.evaluate(async()=>{try{const m=await import('/apps/board/logic.js');let h=m.record(m.createHistory(m.emptyBoard()),{type:'add',column:'todo',text:'a'});h=m.record(m.undo(h),{type:'add',column:'todo',text:'c'});return {future:h.future,texts:h.present.columns.todo.map(c=>c.text)};}catch{return null;}});need(result&&equal(result.future,[])&&equal(result.texts,['c']));});
 await check('import-clears',async()=>{const value={nextId:2,columns:{todo:[{id:'c1',text:'Imported'}],doing:[],done:[]}};await stored(()=>button('import').setInputFiles({name:'board.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(value))}));need(equal(await texts('todo'),['Imported'])&&!await button('undo').isEnabled()&&!await button('redo').isEnabled());
  const result=await page.evaluate(async board=>{try{const m=await import('/apps/board/logic.js');let h=m.record(m.createHistory(m.emptyBoard()),{type:'add',column:'todo',text:'old'});h=m.record(h,{type:'import',board});return {past:h.past,future:h.future,present:h.present};}catch{return null;}},value);need(result&&equal(result.past,[])&&equal(result.future,[])&&equal(result.present,value));});
 await check('shortcuts-reload',async()=>{await add('todo','Keyboard');await page.locator('h1').click();for(const shortcut of ['Control+z','Control+Shift+z','Meta+z','Meta+Shift+z']){await stored(()=>page.keyboard.press(shortcut));need((await texts('todo')).includes('Keyboard')===shortcut.includes('Shift'));}await page.reload();await wait(async()=>await board().getAttribute('data-ready')==='true',false);need(equal(await texts('todo'),['Imported','Keyboard'])&&!await button('undo').isEnabled()&&!await button('redo').isEnabled());});
}
async function puzzleDeadlock(){
 const dead=()=>page.locator('#board .dead');
 const select=async i=>{await page.locator('#level').selectOption(String(i));await wait(async()=>await page.locator('#board .cell').count()>0,false);};
 const moves=async value=>{for(const c of value.toLowerCase())await page.getByTestId('move-'+c).click();};
 await check('deadlock-api',async()=>{await page.goto(origin+'/apps/puzzle/');await wait(async()=>await page.locator('#board .cell').count()>0,false);need(await page.evaluate(async()=>typeof(await import('/apps/puzzle/logic.js')).deadBoxes==='function'));});
 await check('level-starts',async()=>{const result=await page.evaluate(async()=>{try{const m=await import('/apps/puzzle/logic.js'),levels=await(await fetch('/apps/puzzle/levels.json')).json();return levels.map(l=>m.deadBoxes(m.parse(l.map)));}catch{return null;}});need(result&&result.length>0&&result.every(x=>equal(x,[])));});
 await check('corner-indices',async()=>{const result=await page.evaluate(async()=>{try{const m=await import('/apps/puzzle/logic.js'),levels=await(await fetch('/apps/puzzle/levels.json')).json(),s=m.parse(['########','#$ @  $#','# .  . #','########']);s.boxes.reverse();return [m.deadBoxes(m.play(m.parse(levels[1].map),'DLdR')),m.deadBoxes(m.play(m.parse(levels[4].map),'URurDD')),m.deadBoxes(s)];}catch{return null;}});need(equal(result,[[28],[33],[9,14]]));});
 await check('non-dead-cases',async()=>{const result=await page.evaluate(async()=>{try{const m=await import('/apps/puzzle/logic.js');return [m.deadBoxes(m.parse(['####','#@*#','####'])),m.deadBoxes(m.parse(['######','#@$ .#','#    #','######']))];}catch{return null;}});need(equal(result,[[],[]]));});
 await check('corner-warning',async()=>{await select(1);await page.locator('h1').click();for(const key of ['ArrowDown','ArrowLeft','ArrowDown','ArrowRight'])await page.keyboard.press(key);need(await dead().count()===1&&await page.locator('#board .cell').nth(28).evaluate(e=>e.classList.contains('dead')));need((await page.locator('#status').textContent()).trim()==='Stuck: a box is in a corner');});
 await check('undo-restart',async()=>{await page.getByTestId('undo').click();need(await dead().count()===0);need(!(await page.locator('#status').textContent()).includes('Stuck'));await moves('r');need(await dead().count()===1);await page.keyboard.press('z');need(await dead().count()===0);await moves('r');await page.getByTestId('restart').click();need(await dead().count()===0&&!(await page.locator('#status').textContent()).includes('Stuck'));});
 await check('second-level-warning',async()=>{await select(4);await moves('ururdd');need(await dead().count()===1&&await page.locator('#board .cell').nth(33).evaluate(e=>e.classList.contains('dead')));need((await page.locator('#status').textContent()).trim()==='Stuck: a box is in a corner');await page.getByTestId('restart').click();need(await dead().count()===0);});
}
const gpx=segments=>`<gpx><trk>${segments.map(points=>`<trkseg>${points.map(p=>`<trkpt lat="${p[0]}" lon="${p[1]}">${p.length>2?`<ele>${p[2]}</ele>`:''}</trkpt>`).join('')}</trkseg>`).join('')}</trk></gpx>`;
const distance=(a,b)=>{const r=x=>x*Math.PI/180;return 2*6371000*Math.asin(Math.sqrt(Math.sin(r(b[0]-a[0])/2)**2+Math.cos(r(a[0]))*Math.cos(r(b[0]))*Math.sin(r(b[1]-a[1])/2)**2));};
async function routesSegments(){
 const fixture=[[[0,0,100],[0,.01,110]],[[10,10,500],[10,10.01,490],[10,10.02,490]]];const text=gpx(fixture);
 await check('segments-api',async()=>{await page.goto(origin+'/apps/routes/');await wait(async()=>(await page.locator('#stat-distance').textContent()).trim()==='4.02 km',false);const result=await page.evaluate(async text=>{try{const m=await import('/apps/routes/logic.js');const p=m.parseGpx(text);return {segments:p.segments,points:p.points};}catch{return null;}},text);need(result&&Array.isArray(result.segments)&&equal(result.segments.map(x=>x.length),[2,3])&&result.points.length===5&&equal(result.segments.flat(),result.points));});
 await check('gap-distance',async()=>{const expected=fixture.reduce((sum,segment)=>sum+segment.slice(1).reduce((s,p,i)=>s+distance(segment[i],p),0),0);const got=await page.evaluate(async text=>{try{const m=await import('/apps/routes/logic.js'),p=m.parseGpx(text);return m.stats(p.points,{segments:p.segments}).distance;}catch{return null;}},text);need(typeof got==='number'&&Math.abs(got-expected)<1);});
 await check('gap-elevation',async()=>{const got=await page.evaluate(async text=>{try{const m=await import('/apps/routes/logic.js'),p=m.parseGpx(text),s=m.stats(p.points,{segments:p.segments});return [s.gain,s.loss];}catch{return null;}},text);need(equal(got,[10,10]));});
 await check('default-stats',async()=>{const points=fixture.flat();const expected=points.slice(1).reduce((s,p,i)=>s+distance(points[i],p),0);const got=await page.evaluate(async text=>{try{const m=await import('/apps/routes/logic.js'),p=m.parseGpx(text),s=m.stats(p.points);return {distance:s.distance,gain:s.gain,loss:s.loss};}catch{return null;}},text);need(got&&Math.abs(got.distance-expected)<1&&got.gain===400&&got.loss===10);});
 await check('samples-unchanged',async()=>{const got=await page.evaluate(async()=>{try{const m=await import('/apps/routes/logic.js');const out=[];for(const name of ['alpine-climb.gpx','riverside-loop.gpx']){const p=m.parseGpx(await(await fetch('/apps/routes/samples/'+name)).text());out.push({segments:p.segments.length,split:m.stats(p.points,{segments:p.segments}).distance,flat:m.stats(p.points).distance});}return out;}catch{return null;}});need(got&&got.length===2&&got.every((s,i)=>s.segments===1&&Math.abs(s.split-[4020.8,9105.4][i])<1&&Math.abs(s.split-s.flat)<.001));need(await page.locator('#track polyline').count()===1);});
 await check('upload-segments',async()=>{const content=gpx([[[0,0],[0,.01]],[[.01,.01],[.01,.02],[.02,.02]]]);await page.getByTestId('file').setInputFiles({name:'segments.gpx',mimeType:'application/gpx+xml',buffer:Buffer.from(content)});await wait(async()=>(await page.locator('#stat-distance').textContent()).trim()==='3.34 km');need(await page.locator('#track polyline').count()===2);const sizes=await page.locator('#track polyline').evaluateAll(es=>es.map(e=>e.points.numberOfItems));need(equal(sizes,[2,3]));});
 await check('sample-switch',async()=>{const sample=page.locator('#sample');await sample.selectOption('samples/riverside-loop.gpx');await wait(async()=>(await page.locator('#stat-distance').textContent()).trim()==='9.11 km');need(await page.locator('#track polyline').count()===1);await sample.selectOption('samples/alpine-climb.gpx');await wait(async()=>(await page.locator('#stat-distance').textContent()).trim()==='4.02 km');need(await page.locator('#track polyline').count()===1);});
}
const flatLevel=wind=>({spacing:10,terrain:Array(2000).fill(0),gates:[{x:200,y:300,gap:30},{x:600,y:250,gap:30}],...(wind===undefined?{}:{wind})});
const flightReady=async()=>{await page.goto(origin+'/apps/flight/');await wait(async()=>await page.getByTestId('game').getAttribute('data-status')==='flying',false);};
const restartSeed=async seed=>{await page.getByTestId('seed').fill(String(seed));await page.getByTestId('restart').click();};
async function flightWind(){
 const wind=()=>page.getByTestId('wind');const shown=async()=>(await wind().textContent()).trim();
 await check('wind-hud',async()=>{await flightReady();need(await wind().count()===1&&await page.locator('#wind').count()===1&&/^-?\d+ m\/s$/.test(await shown()));});
 let winds;
 await check('wind-seeded',async()=>{winds=await page.evaluate(async()=>{try{const m=await import('/apps/flight/logic.js');return Array.from({length:500},(_,i)=>{const a=m.makeLevel(i+1).wind,b=m.makeLevel(i+1).wind;return a===b?a:null;});}catch{return null;}});need(winds&&winds.every(w=>typeof w==='number'&&w>=-12&&w<=12)&&winds.some(w=>w<0)&&winds.some(w=>w>0));});
 let seeds,first=[];
 await check('wind-display',async()=>{seeds=winds.map((w,i)=>[i+1,w]).filter(([,w])=>Math.abs(w)>=1).slice(0,5);const agrees=(t,w)=>/^-?\d+ m\/s$/.test(t)&&Math.sign(parseInt(t))===Math.sign(w)&&Math.abs(parseInt(t)-w)<=1;
  for(const [seed,w] of seeds){await restartSeed(seed);await wait(async()=>agrees(await shown(),w));first.push(await shown());}need(new Set(first).size>1);});
 await check('wind-reload',async()=>{await page.reload();await wait(async()=>await page.getByTestId('game').getAttribute('data-status')==='flying',false);for(const [i,[seed]] of seeds.entries()){await restartSeed(seed);await wait(async()=>await shown()===first[i]);}});
 await check('ground-speed',async()=>{const head=winds.findIndex(w=>w<-10)+1,tail=winds.findIndex(w=>w>10)+1;need(head&&tail);const speed=async seed=>{await restartSeed(seed);await page.locator('h1').click();await page.waitForTimeout(10000);return Number(await page.getByTestId('speed').textContent());};need(await speed(tail)>await speed(head));});
 await check('tailwind-ground',async()=>{const got=await page.evaluate(async levels=>{try{const m=await import('/apps/flight/logic.js');return levels.map(level=>{let s={...m.initialState(level),vx:m.CRUISE+level.wind};for(let i=0;i<1200;i++)s=m.step(s,{pitch:0,throttle:0},1/60);return s.x;});}catch{return null;}},[flatLevel(10),flatLevel(-10)]);need(got&&got[0]>got[1]);});
 await check('no-wind-unchanged',async()=>{const expected={x:319.13416066070124,y:333.53513326122095,vx:28.366326296726704,vy:-0.37638901249994616,pitch:0.5831232626967157,throttle:0,t:10.000000000000076,status:'flying',score:0,results:[false]};
  const got=await page.evaluate(async level=>{try{const m=await import('/apps/flight/logic.js');let s=m.initialState(level,{y:300});for(let i=0;i<600;i++)s=m.step(s,{pitch:[0,1,0,-1][(i>>5)%4],throttle:i%200<70?1:-1},1/60);const {x,y,vx,vy,pitch,throttle,t,status,score,results}=s;return {x,y,vx,vy,pitch,throttle,t,status,score,results};}catch{return null;}},flatLevel());
  need(got&&Object.entries(expected).every(([k,v])=>typeof v==='number'?Math.abs(got[k]-v)<=1e-9*Math.max(1,Math.abs(v)):equal(got[k],v)));});
}
async function flightReplay(){
 const status=()=>page.getByTestId('game').getAttribute('data-status');const hud=()=>Promise.all(['score','speed','altitude','throttle'].map(id=>page.getByTestId(id).textContent()));
 const runs=[[3,Array.from({length:300},()=>({pitch:-1,throttle:0}))],[5,[...Array.from({length:90},()=>({pitch:0,throttle:1})),...Array.from({length:30},()=>({pitch:1,throttle:1})),...Array.from({length:400},()=>({pitch:-1,throttle:0}))]]];
 await check('replay-api',async()=>{await flightReady();need(await page.evaluate(async()=>{try{const m=await import('/apps/flight/logic.js');return ['encodeRun','decodeRun','replay'].every(k=>typeof m[k]==='function');}catch{return false;}}));});
 const encoded=async()=>page.evaluate(async runs=>{try{const m=await import('/apps/flight/logic.js');const mixed=Array.from({length:500},(_,i)=>({pitch:[-1,0,1][(i>>4)%3],throttle:[1,0,-1,0][(i>>3)%4]}));const all=[...runs,[17,mixed],[4,[]]];
  return {trip:all.every(([seed,inputs])=>JSON.stringify(m.decodeRun(m.encodeRun(seed,inputs)))===JSON.stringify({seed,inputs})),safe:all.every(([seed,inputs])=>/^[A-Za-z0-9_-]+$/.test(m.encodeRun(seed,inputs))),rle:[-1,0,1].every(pitch=>[-1,0,1].every(throttle=>m.encodeRun(123456,Array.from({length:3600},()=>({pitch,throttle}))).length<100))};}catch{return null;}},runs);
 await check('run-roundtrip',async()=>{need((await encoded())?.trip);});
 await check('run-url-safe',async()=>{need((await encoded())?.safe);});
 await check('run-length',async()=>{need((await encoded())?.rle);});
 let predicted;
 await check('replay-fold',async()=>{predicted=await page.evaluate(async runs=>{try{const m=await import('/apps/flight/logic.js');return runs.map(([seed,inputs])=>{const a=m.replay(seed,inputs,1/60),b=inputs.reduce((s,i)=>m.step(s,i,1/60),m.initialState(m.makeLevel(seed)));return JSON.stringify(a)===JSON.stringify(b)?{status:a.status,link:m.encodeRun(seed,inputs)}:null;});}catch{return null;}},runs);need(predicted&&predicted.every(p=>p&&p.status!=='flying'));});
 await check('link-replay',async()=>{for(const [i,[seed]] of runs.entries()){await page.goto(origin+'/apps/flight/?run='+predicted[i].link);await wait(async()=>await page.getByTestId('seed').inputValue()===String(seed));await wait(async()=>await status()===predicted[i].status,true,30000);}});
 await check('keyboard-share',async()=>{await flightReady();await restartSeed(7);await page.locator('h1').click();await page.keyboard.down('ArrowRight');await page.waitForTimeout(500);await page.keyboard.up('ArrowRight');await page.keyboard.down('ArrowDown');await wait(async()=>await status()==='crashed',true,30000);await page.keyboard.up('ArrowDown');const played=await hud();
  await page.getByTestId('share').click();await wait(async()=>new URL(page.url()).searchParams.has('run'));await wait(async()=>await status()==='crashed',true,30000);need(equal(await hud(),played));});
}
const timedGpx=points=>`<gpx><trk><trkseg>${points.map(([lat,lon,s])=>`<trkpt lat="${lat}" lon="${lon}"><time>${new Date(Date.UTC(2026,0,1)+s*1000).toISOString()}</time></trkpt>`).join('')}</trkseg></trk></gpx>`;
async function routesTime(){
 const cell=id=>page.getByTestId(id);const text=async id=>(await cell(id).textContent()).trim();
 const timed=[[0,0,0],[0,.01,600],[0,.01,1500],[0,.02,2100],[0,.02,3723]];
 await check('timing-api',async()=>{await page.goto(origin+'/apps/routes/');await wait(async()=>(await page.locator('#stat-distance').textContent()).trim()==='4.02 km',false);const got=await page.evaluate(async()=>{try{const m=await import('/apps/routes/logic.js');const p=m.parseGpx('<gpx><trk><trkseg><trkpt lat="0" lon="0"><time>2026-01-01T00:00:00Z</time></trkpt><trkpt lat="0" lon="1"/></trkseg></trk></gpx>').points;return typeof m.timing==='function'&&typeof m.formatDuration==='function'&&p[0].time===Date.UTC(2026,0,1)&&!('time' in p[1]);}catch{return false;}});need(got);});
 const timings=async()=>page.evaluate(async text=>{try{const m=await import('/apps/routes/logic.js'),p=m.parseGpx(text).points;return {t:m.timing(p),missing:m.timing([{lat:0,lon:0,ele:null,time:0},{lat:0,lon:.01,ele:null}]),f:[m.formatDuration(3723000),m.formatDuration(null)]};}catch{return null;}},timedGpx(timed));
 await check('timing-stops',async()=>{const moved=distance(timed[0],timed[1])+distance(timed[2],timed[3]);const got=(await timings())?.t;need(got&&got.elapsed===3723000&&got.moving===1200000&&Math.abs(got.avgSpeed-moved/1200)<.01);});
 await check('timing-missing',async()=>{need(equal((await timings())?.missing,{elapsed:null,moving:null,avgSpeed:null}));});
 await check('format-duration',async()=>{need(equal((await timings())?.f,['1:02:03','—']));});
 await check('untimed-default',async()=>{need(await cell('stat-elapsed').count()===1&&await cell('stat-moving').count()===1&&await text('stat-elapsed')==='—'&&await text('stat-moving')==='—');});
 await check('untimed-switch',async()=>{await cell('sample').selectOption('samples/riverside-loop.gpx');await wait(async()=>await text('stat-distance')==='9.11 km');need(await text('stat-elapsed')==='—'&&await text('stat-moving')==='—');});
 await check('timed-upload',async()=>{await cell('file').setInputFiles({name:'timed.gpx',mimeType:'application/gpx+xml',buffer:Buffer.from(timedGpx(timed))});await wait(async()=>await text('stat-elapsed')==='1:02:03'&&await text('stat-moving')==='0:20:00');});
}
try{
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});context=await browser.newContext({serviceWorkers:'block',acceptDownloads:true,recordVideo:{dir:out,size:{width:960,height:720}}});
 await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());await context.tracing.start({screenshots:true,snapshots:true});page=await context.newPage();page.setDefaultTimeout(5000);
 const run={'board-undo-testnet-1':boardUndo,'puzzle-deadlock-testnet-1':puzzleDeadlock,'routes-segments-testnet-1':routesSegments,'flight-wind-testnet-1':flightWind,'flight-replay-testnet-1':flightReplay,'routes-time-testnet-1':routesTime}[task];if(!run)throw new Error('task profile');await run();outcome='passed';
}catch(e){console.error(e.name+': '+String(e.message).slice(0,2000));const functional=e instanceof Assertion;tests.push({id:current,status:functional?'assertion_failed':'infrastructure_failure'});outcome=functional?'functional_failure':'infrastructure_failure';}
finally{try{if(page)await page.screenshot({path:out+'/final.png'});if(context)await context.tracing.stop({path:out+'/trace.zip'});const video=page?.video();if(context)await context.close();if(video)await rename(await video.path(),out+'/video.webm');if(browser)await browser.close();}catch{outcome='infrastructure_failure';}}
console.log(JSON.stringify({outcome,tests}));process.exitCode=outcome==='passed'?0:outcome==='functional_failure'?3:4;
