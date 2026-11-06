import test from 'node:test';
import assert from 'node:assert/strict';
import { ArtifactGuests } from './artifact-guests.mjs';
const scope = '["viewer-chat","app.html"]';
const wallet = '0x' + '1'.repeat(40);
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; }
function fixture(options={}) {
  const events=[],sessions=[],records=[],evidences=[],confirmations=[],owner={};let counter=0;
  const credit={address:wallet,signer:{privateKey:'PRIVATE_WALLET_KEY'},chatCredit:{remainingNanoUsd:'100000000'}};
  const api=async(path,body)=>{
    events.push({type:'api',path,body});
    if(path==='/agent/open'){await options.open?.();return {sessionId:'owned-'+(++counter),seconds:120,grant:{secret:'BEARER_GRANT'},node:{relay_peer:'public-node',receipt_key:'ab'.repeat(32)},rateNanoUsdPerSecond:'10000'};}
    return {active:false,usageUnresolved:false,guestSeconds:2,rateNanoUsdPerSecond:'10000',credit:{spentNanoUsd:'20000'}};
  };
  const createSession=sessionOptions=>{
    const session={options:sessionOptions,lease:null,ended:false,node:{registration:{relay_peer:'public-node',receipt_key:'ab'.repeat(32)}},environment:{privateKey:'PRIVATE_WORKSPACE_KEY'},statusSnapshot:undefined,
      async ensure(signal){
        events.push({type:'ensure'});
        this.lease=await sessionOptions.api('/agent/open',{});
        sessionOptions.changed({state:'held',active:true,lease:this.lease,node:this.node.registration});
        return {callTool:async(request,callOptions)=>{
          events.push({type:'execute',request,signal:callOptions.signal});
          options.onExecute?.();
          if(options.execute)return options.execute(request,callOptions);
          if(options.commandError)return {isError:true,content:[{type:'text',text:'command exited 1'}]};
          return {content:[{type:'text',text:'public-output'}],isError:false,_meta:{secret:'INTERNAL_TOOL_META'}};
        }};
      },
      async status(){
        events.push({type:'status'});
        this.statusSnapshot={active:!this.ended,usageUnresolved:!!options.unresolved&&this.ended,guestSeconds:2,rateNanoUsdPerSecond:'10000',credit:{spentNanoUsd:'20000'}};
        sessionOptions.changed({...this.statusSnapshot,state:options.unresolved?'sealing':'released',lease:this.lease,node:this.node.registration});
        return this.statusSnapshot;
      },
      async restore(){events.push({type:'restore'});this.lease={sessionId:sessionOptions.savedLease.sessionId};return this.status();},
      async end(){events.push({type:'end',sessionId:this.lease?.sessionId||sessionOptions.savedLease?.sessionId});this.ended=true;await this.status();if(!options.unresolved)this.lease=null;},
    };
    sessions.push(session);return session;
  };
  const guests=new ArtifactGuests({credit,api,authorize:async(c,action,fields)=>({wallet:c.address,action,...fields}),createSession,
    confirm:async(details,signal)=>{confirmations.push({details,signal});return options.confirm?options.confirm(details,signal):true;},
    persist:async record=>{events.push({type:'persist',record:structuredClone(record)});records.push(structuredClone(record));await options.persist?.(record);},
    evidence:async record=>{evidences.push(record);},mainHeld:()=>!!options.mainHeld,initial:options.initial||[]});
  return {guests,events,sessions,records,evidences,confirmations,credit,owner,options,
    run:(id='request-one')=>guests.run(scope,{command:'printf public-output',timeoutSeconds:1},{requestId:id,owner,filename:'app.html'})};
}

test('cancelled trusted confirmation cannot create or claim a guest',async()=>{
  const f=fixture({confirm:async()=>false});
  await assert.rejects(f.run(),error=>error.code==='USER_CANCELLED');
  assert.equal(f.confirmations.length,1);assert.equal(f.sessions.length,0);
  assert.equal(f.events.filter(e=>e.type==='api').length,0);
});

test('each approved call has a fresh ephemeral conversation and exposes only public result/evidence',async()=>{
  const f=fixture();const one=await f.run('one'),two=await f.run('two');
  assert.equal(f.confirmations.length,2);assert.equal(f.sessions.length,2);
  const [a,b]=f.sessions.map(s=>s.options);assert.notEqual(a.conversationId,b.conversationId);
  assert.match(a.conversationId,/^artifact-[0-9a-f-]{36}$/);
  assert.equal(a.credit.address,wallet);assert.deepEqual([...a.repository()],[]);
  assert.equal(await a.workspace.latest(),null);assert.equal(await a.workspace.bind(),false);assert.equal(await a.workspace.save(),null);
  const publicData=JSON.stringify({one,two,evidence:f.evidences});
  assert(publicData.includes('public-output'));
  for(const secret of ['PRIVATE_WALLET_KEY','PRIVATE_WORKSPACE_KEY','BEARER_GRANT','INTERNAL_TOOL_META'])assert(!publicData.includes(secret));
  assert.deepEqual(f.events.filter(e=>e.type==='end').map(e=>e.sessionId),['owned-1','owned-2']);
});

test('a held main-chat guest or concurrent request cannot be reused or displaced',async()=>{
  const held=fixture({mainHeld:true});await assert.rejects(held.run());assert.equal(held.sessions.length,0);assert.equal(held.events.some(e=>e.type==='api'&&e.path==='/agent/open'),false);
  const consent=deferred(),f=fixture({confirm:()=>consent.promise});const first=f.run('one');
  await tick();await assert.rejects(f.run('two'));assert.equal(f.sessions.length,0);
  consent.resolve(false);await assert.rejects(first,error=>error.code==='USER_CANCELLED');
});

test('a known claim is durably recorded before any command executes',async()=>{
  const gate=deferred(),claimed=deferred();
  const f=fixture({persist:async record=>{if(record.sessionId&&record.state==='claimed'){claimed.resolve();await gate.promise;}}});
  const running=f.run();await claimed.promise;
  assert.equal(f.events.some(e=>e.type==='execute'),false);
  gate.resolve();await running;assert.equal(f.events.filter(e=>e.type==='execute').length,1);
});

test('claim persistence failure ends only that known claim before execution',async()=>{
  let fail=true;const f=fixture({persist:async record=>{if(fail&&record.sessionId){fail=false;throw Error('durable storage failed');}}});
  await assert.rejects(f.run(),/durable storage failed/);
  assert.equal(f.events.some(e=>e.type==='execute'),false);
  const end=f.events.find(e=>e.type==='api'&&e.path==='/agent/end');assert.equal(end?.body.sessionId,'owned-1');
});

test('command error and owner disposal end the owned guest without replaying work',async()=>{
  const failed=fixture({commandError:true});await failed.run().catch(()=>{});
  assert.equal(failed.events.filter(e=>e.type==='execute').length,1);assert.deepEqual(failed.events.filter(e=>e.type==='end').map(e=>e.sessionId),['owned-1']);
  const started=deferred();const f=fixture({onExecute:()=>started.resolve(),execute:(_r,{signal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}))});
  const run=f.run();const rejected=assert.rejects(run);await started.promise;
  f.guests.cancel(scope,'request-one',{});assert.equal(f.events.find(e=>e.type==='execute').signal.aborted,false);
  await f.guests.cancelOwner(f.owner);await rejected;
  assert.equal(f.events.filter(e=>e.type==='execute').length,1);assert.deepEqual(f.events.filter(e=>e.type==='end').map(e=>e.sessionId),['owned-1']);
});

test('unresolved usage retains its claim and reload recovery performs cleanup only',async()=>{
  const f=fixture({unresolved:true});await f.run().catch(()=>{});
  const pending=[...f.records].reverse().find(r=>r.state==='release-pending');assert(pending);assert.equal(f.records.some(r=>r.state==='released'),false);
  const restored=fixture({initial:[pending],unresolved:true});
  await restored.guests.recover(pending).catch(()=>{});
  assert.equal(restored.events.some(e=>e.type==='ensure'||e.type==='execute'),false);
  assert.equal(restored.events.some(e=>e.type==='api'&&e.path==='/agent/open'),false);
  restored.options.unresolved=false;await restored.guests.finish(pending);
  assert(restored.records.some(r=>r.state==='released'));
  assert(restored.events.filter(e=>e.type==='end').every(e=>e.sessionId==='owned-1'));
});

test('switching the viewer wallet during confirmation cannot claim a guest',async()=>{
  const consent=deferred(),f=fixture({confirm:()=>consent.promise});const run=f.run();
  const rejected=assert.rejects(run,error=>error.code==='PERMISSION_DENIED');
  await tick();f.credit.address='0x'+'2'.repeat(40);consent.resolve(true);await rejected;
  assert.equal(f.sessions.length,0);assert.equal(f.events.some(e=>e.type==='api'&&e.path==='/agent/open'),false);
});

test('disposing during claim persistence still ends the known server claim before it is assigned to the session',async()=>{
  const gate=deferred(),claimed=deferred();
  const f=fixture({persist:async record=>{if(record.sessionId&&record.state==='claimed'){claimed.resolve();await gate.promise;}}});
  const run=f.run();const rejected=assert.rejects(run);await claimed.promise;
  assert.equal(f.sessions[0].lease,null);
  f.guests.cancelOwner(f.owner);await rejected;
  const ended=f.events.find(e=>e.type==='api'&&e.path==='/agent/end');
  gate.resolve();await tick();
  assert.equal(ended?.body.sessionId,'owned-1','a durably pending callback must not hide the already known claim from cleanup');
  assert.equal(f.events.some(e=>e.type==='execute'),false);
  assert.deepEqual(f.guests.pending,[]);assert.equal(f.guests.busy,false);
  assert.equal(f.records.at(-1).state,'released');
  assert.equal(f.events.filter(e=>e.type==='ensure').length,1);
});

test('a late open response after cancellation is ended without resurrecting or executing its lease',async()=>{
  const opening=deferred(),arrived=deferred();
  const f=fixture({open:async()=>{arrived.resolve();await opening.promise;}});
  const run=f.run();const rejected=assert.rejects(run);await arrived.promise;
  f.guests.cancelOwner(f.owner);await rejected;
  assert.equal(f.sessions[0].lease,null);assert.deepEqual(f.guests.pending,[]);
  opening.resolve();await tick();
  const ended=f.events.find(e=>e.type==='api'&&e.path==='/agent/end');
  assert.equal(ended?.body.sessionId,'owned-1');assert.equal(f.events.some(e=>e.type==='execute'),false);
  assert.deepEqual(f.guests.pending,[]);assert.equal(f.guests.busy,false);assert.equal(f.records.at(-1).state,'released');
});
