import test from "node:test";
import assert from "node:assert/strict";
import { participationView } from "./participation.mjs";
const report = {
  version:1, state:"observed", observed_at:"2030-01-01T00:00:00Z", max_age:90,
  observation_source:"operator-rpc-relay", chain_id:84532, registry:"0x"+"1".repeat(40), protocol_version:2,
  block:{number:100,hash:"0x"+"2".repeat(64),timestamp:1893456000},
  coverage:{from_block:100,to_block:100,opt_in_identities:1,complete_census:false,selection:"operator-supplied-public-opt-in-roster"},
  network_paused:false,relay:{state:"observed",sponsor_writes_paused:false},
  shared_key:{scope:"0x"+"0".repeat(64),epoch:"1",committed:true,public_key_sha256:"3".repeat(64)},
  members:[{member_id:"0x"+"4".repeat(64),category:"0x"+"5".repeat(64),registered:true,last_checked:1893455900,revoked:false,liveness:"unknown",source:"operator-opt-in"}],
  independent_operator_count:null,independent_device_count:null,liveness:"unknown",
};
const now=1893456000;
test("scoped registration records expire locally without asserting live peers",()=>{
  const result=participationView(report,now);
  assert.equal(result.status,"observed");assert.equal(result.details.members[0].liveness,"unknown");
  assert.equal(result.details.independent_operator_count,null);
  assert.equal(participationView(report,now+90).status,"observed");
  assert.equal(participationView(report,now+91).status,"stale");
  assert.equal(participationView(report,now-31).status,"unknown");
  assert.equal(participationView(report,now-30).status,"observed");
  const absent=structuredClone(report);absent.shared_key={...absent.shared_key,committed:false,public_key_sha256:null};
  absent.members[0]={...absent.members[0],registered:false,last_checked:null,category:"0x"+"0".repeat(64),source:"operator-opt-in"};
  assert.equal(participationView(absent,now).status,"observed");
  absent.members=[]; absent.coverage.opt_in_identities=0;
  assert.equal(participationView(absent,now).details.members.length,0);
});
test("an explicit observation failure stays unknown",()=>{
  const failed={version:1,state:"unknown",observed_at:report.observed_at,max_age:90,
    observation_source:"operator-rpc-relay",reason:"observation-unavailable",members:[],
    independent_operator_count:null,independent_device_count:null,liveness:"unknown"};
  assert.equal(participationView(failed,now).details,null);
  assert.match(participationView(failed,now).observation,/could not obtain/);
  assert.equal(participationView({...failed,reason:"private error"},now).observation,"No valid participation observation.");
});
test("refuse invented census, liveness, extra fields, inconsistent coverage, and unbounded records",()=>{
  const changes=[
    v=>{v.private="canary";},v=>{v.version=2;},v=>{v.independent_operator_count=1;},v=>{v.liveness="online";},
    v=>{v.chain_id=8453;},v=>{v.observed_at="2030-02-31T00:00:00Z";},v=>{v.observed_at="invalid";},v=>{v.max_age=3600;},
    v=>{v.coverage.complete_census=true;},v=>{v.coverage.to_block=101;},v=>{v.coverage.from_block=102;},
    v=>{v.block.timestamp=now-121;},v=>{v.block.timestamp=now+16;},
    v=>{v.shared_key.scope="0x"+"1".repeat(64);},v=>{v.shared_key.epoch="18446744073709551616";},
    v=>{v.members[0].last_checked=now+1;},v=>{v.members[0].registered=false;},v=>{v.members[0].last_checked=null;},
    v=>{v.block.hash="invalid";},v=>{v.shared_key.epoch="-1";},v=>{v.shared_key.committed=false;},
    v=>{v.relay.sponsor_writes_paused="false";},v=>{v.members[0].liveness="online";},
    v=>{v.members[0].last_checked=Infinity;},v=>{v.members[0].owner="private";},
    v=>{v.members.push({...v.members[0]});},v=>{v.members=Array(65).fill(v.members[0]);},
  ];
  for(const change of changes){const value=structuredClone(report);change(value);assert.equal(participationView(value,now).status,"unknown");assert.equal(participationView(value,now).details,null);}
});
