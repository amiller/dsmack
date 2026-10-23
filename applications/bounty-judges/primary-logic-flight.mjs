// Complete original flight logic vectors. Candidate module runs ONLY in Chromium.
// All comparisons/thresholds are evaluated by trusted Node assertions.
import assert from 'node:assert/strict';
export const CASE_IDS=Object.freeze([
  'seeded rng is deterministic and in [0,1)',
  'levels are pure data from the seed',
  'generated gates clear the terrain and are ordered',
  'terrainAt interpolates linearly and clamps at the ends',
  'trim balances forces in level flight at cruise',
  'level flight at cruise holds altitude and speed for a minute',
  'a speed disturbance damps out instead of diverging',
  'lift is linear below the critical angle and collapses past it',
  'pulling up hard at low speed stalls and the plane sinks',
  'the same pitch-up at cruise speed climbs without stalling',
  'throttle accelerates and stays within [0, 1]',
  'flying through a gate scores, missing it does not',
  'hitting the terrain crashes and freezes the state',
  'same seed and inputs give identical flights',
  'hands-off flight through a generated level is deterministic and ends',
]);
export async function runLogic(page){
  const value=await page.evaluate(async()=>{
    const L=await import('/apps/flight/logic.js');
    const DT=1/60,flat=(gates=[])=>({spacing:10,terrain:Array(2000).fill(0),gates});
    const run=(s,input,seconds)=>{for(let i=0;i<Math.round(seconds/DT);i++)s=L.step(s,input,DT);return s;};
    const speed=s=>Math.hypot(s.vx,s.vy);
    const rngA=Array.from({length:1000},L.mulberry32(42)),rngB=Array.from({length:1000},L.mulberry32(42));
    const levels=Array.from({length:50},(_,i)=>{
      const level=L.makeLevel(i+1);
      return {gates:level.gates.map(g=>({x:g.x,y:g.y,gap:g.gap,ground:L.terrainAt(level,g.x)})),terrain:level.terrain};
    });
    const trim=L.initialState(flat()),forces=L.forces(trim);
    const cruise=run(L.initialState(flat()),{},60);
    const disturbed={...L.initialState(flat(),{y:300}),vx:46},late=run(disturbed,{},50);
    const swing=s=>{let lo=Infinity,hi=-Infinity;for(let i=0;i<600;i++){s=L.step(s,{},DT);lo=Math.min(lo,s.y);hi=Math.max(hi,s.y);}return hi-lo;};
    let stalled={...L.initialState(flat(),{y:300,speed:22}),throttle:0};stalled=run(stalled,{pitch:1},0.5);
    const initialStall={stalled:stalled.stalled,y:stalled.y};stalled=run(stalled,{},2);
    let climb=run(L.initialState(flat(),{y:300}),{pitch:1},0.1);const initialClimbStalled=climb.stalled;climb=run(climb,{},1);
    const accelerated=run(L.initialState(flat(),{y:300}),{throttle:1},5);
    const hit=run(L.initialState(flat([{x:200,y:120,gap:30}])),{},6);
    const miss=run(L.initialState(flat([{x:200,y:160,gap:30},{x:400,y:120,gap:30}])),{},12);
    const crashed=run(run(L.initialState(flat()),{pitch:-1},0.5),{},10);
    const inputs=Array.from({length:1200},(_,i)=>({pitch:[0,1,0,-1][(i>>6)%4],throttle:i%300<100?1:0}));
    const fly=()=>inputs.reduce((s,inp)=>L.step(s,inp,DT),L.initialState(L.makeLevel(99)));
    const handsOff=()=>run(L.initialState(L.makeLevel(7)),{},120);
    const level=L.makeLevel(7);
    return {rngA,rngB,rngOther:Array.from({length:5},L.mulberry32(43)),
      level,levelAgain:L.makeLevel(7),otherTerrain:L.makeLevel(8).terrain,roundTrip:JSON.parse(JSON.stringify(L.makeLevel(7))),levels,
      terrain:[5,15,-50,999].map(x=>L.terrainAt({spacing:10,terrain:[0,10,30]},x)),
      trim:{ax:forces.ax,ay:forces.ay,throttle:trim.throttle},cruise:{status:cruise.status,y:cruise.y,speed:speed(cruise),target:L.CRUISE},
      disturbance:{lateSwing:swing(late),earlySwing:swing(disturbed),laterSpeed:speed(run(late,{},30)),target:L.CRUISE,y:late.y},
      lift:[L.cl(0.1),L.cl(0.05),L.cl(L.ALPHA_STALL+0.01),L.cl(L.ALPHA_STALL-0.01),L.cl(-0.4),L.cl(0.4)],
      initialStall,stallEnd:{stalled:stalled.stalled,y:stalled.y,vy:stalled.vy},initialClimbStalled,climb:{y:climb.y,vy:climb.vy},
      acceleration:{throttle:accelerated.throttle,speed:speed(accelerated),target:L.CRUISE,minimum:run(accelerated,{throttle:-1},5).throttle},
      hit:{score:hit.score,results:hit.results,status:hit.status},miss:{score:miss.score,results:miss.results,next:miss.next},
      crash:{status:crashed.status,sameIdentity:L.step(crashed,{throttle:1},DT)===crashed},flightA:fly(),flightB:fly(),handsOffA:handsOff(),handsOffB:handsOff()};
  });
  assert.deepEqual(value.rngA,value.rngB);assert.equal(value.rngA.length,1000);
  assert.ok(value.rngA.every(x=>x>=0&&x<1));assert.notDeepEqual(value.rngA.slice(0,5),value.rngOther);
  assert.deepEqual(value.level,value.levelAgain);assert.notDeepEqual(value.level.terrain,value.otherTerrain);assert.deepEqual(value.roundTrip,value.level);
  assert.equal(value.levels.length,50);
  for(const [index,level] of value.levels.entries()){
    assert.equal(level.gates.length,12);
    for(const [i,g] of level.gates.entries()){
      assert.ok(g.y-g.gap/2>=g.ground+20,`seed ${index+1} gate ${i}`);
      if(i)assert.ok(g.x>level.gates[i-1].x);
    }
    assert.ok(level.terrain.every(h=>h>0&&h<100));
  }
  assert.deepEqual(value.terrain,[5,20,0,30]);
  assert.ok(Math.abs(value.trim.ax)<1e-9&&Math.abs(value.trim.ay)<1e-9);assert.ok(value.trim.throttle>0&&value.trim.throttle<1);
  assert.equal(value.cruise.status,'flying');assert.ok(Math.abs(value.cruise.y-120)<1e-6);assert.ok(Math.abs(value.cruise.speed-value.cruise.target)<1e-6);
  assert.ok(value.disturbance.lateSwing<value.disturbance.earlySwing/4);assert.ok(Math.abs(value.disturbance.laterSpeed-value.disturbance.target)<1);assert.ok(Math.abs(value.disturbance.y-300)<20);
  assert.equal(value.lift[0],2*value.lift[1]);assert.ok(value.lift[2]<0.5*value.lift[3]);assert.equal(value.lift[4],-value.lift[5]);
  assert.ok(value.initialStall.stalled);assert.ok(value.stallEnd.stalled);assert.ok(value.stallEnd.y<value.initialStall.y-5&&value.stallEnd.vy<0);
  assert.ok(!value.initialClimbStalled);assert.ok(value.climb.y>300&&value.climb.vy>0);
  assert.equal(value.acceleration.throttle,1);assert.ok(value.acceleration.speed>value.acceleration.target+1);assert.equal(value.acceleration.minimum,0);
  assert.equal(value.hit.score,1);assert.deepEqual(value.hit.results,[true]);assert.equal(value.hit.status,'finished');
  assert.equal(value.miss.score,1);assert.deepEqual(value.miss.results,[false,true]);assert.equal(value.miss.next,2);
  assert.equal(value.crash.status,'crashed');assert.equal(value.crash.sameIdentity,true);
  assert.deepEqual(value.flightA,value.flightB);assert.notEqual(value.handsOffA.status,'flying');assert.deepEqual(value.handsOffA,value.handsOffB);
  return [...CASE_IDS];
}
