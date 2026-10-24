import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ConsoleObserver, observe } from './observe.mjs';
test('public host lifecycle projection never forwards prompts, hex logs or tool arguments',()=>{const o=new ConsoleObserver();const phases=o.feed(Buffer.from('DSMACK_SUPERVISOR_START linux\nDSMACK_DOCKERD_READY\nprivate arbitrary prompt\nDSMACK_DIAGNOSTIC hex=secret\nDSMACK_BROKER_READY task\nDSMACK_RUNNER_DONE failures=0\nDSMACK_POWERING_OFF\n'));assert.deepEqual(phases.map(x=>x.phase),['boot','pull','agent','review','done']);assert.equal(JSON.stringify(phases).includes('private'),false);});
test('split console frames preserved; large diagnostics discarded',()=>{const o=new ConsoleObserver();assert.deepEqual(o.feed(Buffer.from('DSMACK_SUPER')),[]);assert.equal(o.feed(Buffer.from('VISOR_START linux\n'))[0].phase,'boot');assert.deepEqual(o.feed(Buffer.from('x'.repeat(70000)+'\n')),[]);});
test('actual file observation exits on guest marker but never claims verification',async()=>{const d=mkdtempSync(join(tmpdir(),'bounty-observer-'));try{const p=join(d,'console');writeFileSync(p,'DSMACK_BROKER_READY task\nDSMACK_POWERING_OFF\n');const sent=[];const r=await observe({consolePath:p,attempt:'a'.repeat(32),url:'http://127.0.0.1:1',duration:1,send:async e=>sent.push(e)});assert.deepEqual(r,{observed_guest_poweroff:true,verified:false});assert.equal(sent.length,2);symlinkSync(p,join(d,'link'));await assert.rejects(()=>observe({consolePath:join(d,'link'),attempt:'a'.repeat(32),url:'http://localhost:1',duration:1,send:async()=>{}}));}finally{rmSync(d,{recursive:true,force:true});}});
