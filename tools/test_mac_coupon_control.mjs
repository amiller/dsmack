import test from 'node:test';import assert from 'node:assert/strict';import crypto from 'node:crypto';
import {verifyControl} from './mac_coupon_control.mjs';import {readControlChallenge,connectMacControl} from '../node/mac-coupon-control.mjs';
const domain='dsmack-coupon-mac-control-v1',challenge='11'.repeat(32),composeHash='22'.repeat(32),cdhash='33'.repeat(32);
const key=crypto.generateKeyPairSync('ed25519');const pub=key.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const binding={version:1,challenge_hex:challenge,compose_hash:composeHash,public_key_hex:pub};
const canonical=v=>JSON.stringify(Object.fromEntries(Object.entries(v).sort()));const data=domain+'|'+crypto.createHash('sha256').update(canonical(binding)).digest('hex');
const value={binding,evidence:{synthetic:true},possession_signature_hex:crypto.sign(null,Buffer.from(domain+'\0'+data),key.privateKey).toString('hex')};
const options={challenge,composeHash,cdhash,verifyRunner:(ev,opts)=>{assert.deepEqual(ev,{synthetic:true});assert.equal(opts.expectData,data);assert.deepEqual(opts.cdhashes,[cdhash]);assert.deepEqual(opts.composeHashes,[composeHash]);}};
test('synthetic possession proof binds fresh challenge and exact pinned runtime',()=>assert.equal(verifyControl(value,options).issuer_public_key_hex,pub));
test('nonce/compose/key/schema/signature substitutions refuse',()=>{for(const [field,replacement] of [['challenge_hex','44'.repeat(32)],['compose_hash','44'.repeat(32)],['public_key_hex','44'.repeat(32)],['version',true],['extra',true]]){const bad=structuredClone(value);bad.binding[field]=replacement;assert.throws(()=>verifyControl(bad,options));}const bad=structuredClone(value);bad.possession_signature_hex='00'.repeat(64);assert.throws(()=>verifyControl(bad,options));});
test('hardware verifier refusal cannot be replaced by possession alone',()=>assert.throws(()=>verifyControl(value,{...options,verifyRunner:()=>{throw Error('fixture hardware refusal');}})));
test('strict challenge schema refuses before reading any control',async()=>{async function* lines(v){yield Buffer.from(JSON.stringify(v));}assert.equal(await readControlChallenge(lines({op:'challenge',challenge_hex:challenge})),challenge);for(const v of [{op:'challenge',challenge_hex:'00'},{op:'other',challenge_hex:challenge},{op:'challenge',challenge_hex:challenge,secret:'x'}])await assert.rejects(()=>readControlChallenge(lines(v)));});
test('invalid port refuses before runner socket',async()=>{for(const p of [80,'18890',-1,65536])await assert.rejects(()=>connectMacControl(p));});

import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import net from 'node:net';import readline from 'node:readline';import {once} from 'node:events';import {PassThrough} from 'node:stream';import {hold} from './mac_coupon_control.mjs';
async function fixture(){
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'mac-control-test-'));await fs.chmod(dir,0o700);
 const reservation=net.createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));const port=reservation.address().port;await new Promise(r=>reservation.close(r));
 const input=new PassThrough();const holder=await hold({dir,port,composeHash,cdhash,input,verifyRunner:(ev,opts)=>{assert.equal(ev.synthetic,true);assert.ok(opts.expectData.startsWith(domain+'|'));}});
 return {dir,port,input,holder,async close(){await holder.close();input.destroy();await fs.rm(dir,{recursive:true,force:true});}};
}
async function connect(f){const socket=net.connect(f.port,'127.0.0.1');await once(socket,'connect');const lines=readline.createInterface({input:socket})[Symbol.asyncIterator]();const nonce=JSON.parse((await lines.next()).value).challenge_hex;return {socket,lines,nonce};}
function proof(nonce){const b={...binding,challenge_hex:nonce};const d=domain+'|'+crypto.createHash('sha256').update(canonical(b)).digest('hex');return {binding:b,evidence:{synthetic:true},possession_signature_hex:crypto.sign(null,Buffer.from(domain+'\0'+d),key.privateKey).toString('hex')};}
test('actual loopback duplex sends controls only after proof and privately retains replies', {timeout:5000},async()=>{
 const f=await fixture();try{
 await fs.writeFile(path.join(f.dir,'approval.json'),'{"signed":"approval"}',{mode:0o600});await fs.writeFile(path.join(f.dir,'config.json'),'{"signed":"config"}',{mode:0o600});
 const c=await connect(f);assert.equal(await fs.readFile(path.join(f.dir,'operator-output.jsonl'),'utf8'),'');
 c.socket.write(JSON.stringify(proof(c.nonce))+'\n'+JSON.stringify({op:'bootstrap_metadata',public_key_hex:pub})+'\n');
 assert.equal(JSON.parse((await c.lines.next()).value).signed,'approval');assert.equal(JSON.parse((await c.lines.next()).value).signed,'config');
 c.socket.write(JSON.stringify({id:'test',ok:true,result:{coupon:'synthetic-test-only'}})+'\n');
 f.input.write('{"op":"test"}\n');assert.equal(JSON.parse((await c.lines.next()).value).op,'test');
 for(let i=0;i<40;i++){const text=await fs.readFile(path.join(f.dir,'operator-output.jsonl'),'utf8');if(text.includes('synthetic-test-only'))break;await new Promise(r=>setTimeout(r,10));}
 const output=await fs.readFile(path.join(f.dir,'operator-output.jsonl'),'utf8');assert.equal(output.trim().split('\n').length,2);assert.ok(output.includes('synthetic-test-only'));assert.equal((await fs.stat(path.join(f.dir,'operator-output.jsonl'))).mode&0o777,0o600);
 c.socket.end();await once(c.socket,'close');assert.equal(f.input.listenerCount('data'),0);
 }finally{await f.close();}
});
test('failed proof sends no controls; a subsequent genuine test proof can connect; seed reply refuses',{timeout:5000},async()=>{
 const f=await fixture();try{
 await fs.writeFile(path.join(f.dir,'approval.json'),'{}',{mode:0o600});await fs.writeFile(path.join(f.dir,'config.json'),'{}',{mode:0o600});
 const bad=await connect(f);bad.socket.write(JSON.stringify(proof('00'.repeat(32)))+'\n');await once(bad.socket,'close');assert.equal(await fs.readFile(path.join(f.dir,'operator-output.jsonl'),'utf8'),'');
 const c=await connect(f);c.socket.write(JSON.stringify(proof(c.nonce))+'\n');await c.lines.next();await c.lines.next();c.socket.write('{"noise_seed_hex":"refused"}\n');await once(c.socket,'close');assert.equal(await fs.readFile(path.join(f.dir,'operator-output.jsonl'),'utf8'),'');
 }finally{await f.close();}
});
