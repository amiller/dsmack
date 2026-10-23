// Complete original routes suite, immutable original GPX bytes supplied by Node.
// Candidate calculations run only in Chromium; Node owns every comparison.
import assert from 'node:assert/strict';
import {readFile,lstat} from 'node:fs/promises';
export const CASE_IDS=Object.freeze([
  'parses alpine sample','parses riverside sample as a closed loop',
  'parses self-closing trkpt, single quotes and missing ele',
  'rejects GPX without points or with bad coordinates','haversine matches known distances',
  'sample distances','gain and loss on synthetic tracks','sample elevation stats and bbox',
  'profile is cumulative distance','project fits box, preserves aspect, north up',
  'profileCoords spans the box','formatting',
]);
async function fixture(name){
  const file=new URL('./primary-original/apps/routes/samples/'+name,import.meta.url),s=await lstat(file);
  assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=262144,'selected original GPX fixture');
  const raw=await readFile(file);assert.equal(raw.length,s.size);return new TextDecoder('utf-8',{fatal:true}).decode(raw);
}
export async function runLogic(page){
  const fixtures={alpine:await fixture('alpine-climb.gpx'),riverside:await fixture('riverside-loop.gpx')};
  const v=await page.evaluate(async({alpine,riverside})=>{
    const L=await import('/apps/routes/logic.js');
    const sample=raw=>L.parseGpx(raw),track=eles=>eles.map((ele,i)=>({lat:0,lon:i*0.001,ele}));
    const a=sample(alpine),r=sample(riverside);
    const malformed=['<gpx></gpx>','<trkpt lat="1"/>','<trkpt lat="x" lon="1"/>'].map(raw=>{
      try{L.parseGpx(raw);return {threw:false,message:''};}catch(error){return {threw:true,message:String(error.message)};}
    });
    return {alpine:a,riverside:r,
      flexible:L.parseGpx(`<gpx><trk><trkseg><trkpt lon='2' lat='1'/><trkpt lat="3" lon="4"><ele> 5.5 </ele></trkpt></trkseg></trk></gpx>`),
      malformed,radius:L.EARTH_RADIUS_M,
      distances:[L.haversine({lat:0,lon:0},{lat:1,lon:0}),L.haversine({lat:0,lon:0},{lat:0,lon:180}),
        L.haversine({lat:48.8566,lon:2.3522},{lat:51.5074,lon:-0.1278}),L.haversine({lat:10,lon:10},{lat:10,lon:10})],
      sampleStats:{alpine:L.stats(a.points),riverside:L.stats(r.points)},
      synthetic:[L.stats(track([100,150,120,200])),L.stats(track([5,5,5])),L.stats(track([10,null,30,20])),L.stats(track([null,null]))],
      profile:L.profile(track([1,2,3])),
      project:L.project([{lat:0,lon:0},{lat:1,lon:2}],300,300,10),
      projectVertical:L.project([{lat:60,lon:0},{lat:61,lon:0}],100,100),
      coords:L.profileCoords(L.profile(track([0,50,100])),200,100,0),
      formatted:[L.formatKm(4020.83),L.formatM(865.1),L.formatM(null)]};
  },fixtures);
  const near=(a,b,tol)=>assert.ok(Math.abs(a-b)<=tol,`${a} not within ${tol} of ${b}`);
  assert.equal(v.alpine.name,'Alpine Switchback Climb');assert.equal(v.alpine.points.length,220);
  assert.deepEqual(v.alpine.points[0],{lat:45.9237,lon:6.869448,ele:1034.6});
  assert.equal(v.riverside.name,'Riverside Loop');assert.equal(v.riverside.points.length,301);
  assert.deepEqual(v.riverside.points.at(-1),v.riverside.points[0]);
  assert.equal(v.flexible.name,null);assert.deepEqual(v.flexible.points,[{lat:1,lon:2,ele:null},{lat:3,lon:4,ele:5.5}]);
  for(const [i,pattern] of [/no <trkpt>/,/missing lon/,/bad trkpt/].entries()){
    assert.equal(v.malformed[i].threw,true);assert.match(v.malformed[i].message,pattern);
  }
  near(v.distances[0],v.radius*Math.PI/180,1e-6);near(v.distances[1],v.radius*Math.PI,1e-6);
  near(v.distances[2],343560,500);assert.equal(v.distances[3],0);
  near(v.sampleStats.alpine.distance,4020.8,1);near(v.sampleStats.riverside.distance,9105.4,1);
  assert.deepEqual([v.synthetic[0].gain,v.synthetic[0].loss],[130,30]);
  assert.equal(v.synthetic[1].gain,0);assert.equal(v.synthetic[1].loss,0);
  assert.equal(v.synthetic[2].gain,20);assert.equal(v.synthetic[2].loss,10);
  assert.deepEqual([v.synthetic[3].gain,v.synthetic[3].minEle,v.synthetic[3].maxEle],[0,null,null]);
  const s=v.sampleStats.riverside;near(s.gain,s.loss,1e-9);assert.equal(s.minEle,11.7);assert.equal(s.maxEle,20.2);
  assert.deepEqual(s.bbox,{minLat:51.4672,maxLat:51.4928,minLon:-0.242,maxLon:-0.198});
  near(v.sampleStats.alpine.gain,865.1,1e-9);
  assert.equal(v.profile[0].d,0);near(v.profile[2].d,2*v.profile[1].d,1e-9);assert.deepEqual(v.profile.map(x=>x.ele),[1,2,3]);
  assert.deepEqual(v.project.map(pt=>pt.map(Math.round)),[[10,220],[290,80]]);assert.deepEqual(v.projectVertical,[[50,100],[50,0]]);
  assert.deepEqual(v.coords.map(([x])=>Math.round(x)),[0,100,200]);assert.deepEqual(v.coords.map(([,y])=>y),[100,50,0]);
  assert.deepEqual(v.formatted,['4.02 km','865 m','—']);
  return [...CASE_IDS];
}
