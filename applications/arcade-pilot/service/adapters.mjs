import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFileSync,lstatSync} from 'node:fs';
import {need,sha} from './core.mjs';
const exec=promisify(execFile);
export function pinnedFile(p){need(p&&typeof p.path==='string'&&p.path.startsWith('/')&&lstatSync(p.path).isFile()&&sha(readFileSync(p.path))===p.sha256,'executable pin mismatch');return p.path;}
export function walletVerifier(config){const cast=pinnedFile(config);return async({payee,message,signature})=>{try{const r=await exec(cast,['wallet','verify','--address',payee,message,signature],{timeout:10000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin'}});return /valid|success/i.test(r.stdout)&&!/invalid|unsuccess/i.test(r.stdout);}catch{return false;}};}
// Authority lives on the selected Zed worker, not in this public HTTP container.
export function remoteAdapters(pilot,verifyWallet){return {verifyWallet,register:i=>pilot.enqueue('registration',i),prepareExecution:i=>pilot.enqueue('prepareExecution',i),verifyEvidence:i=>pilot.enqueue('verifyEvidence',i),claim:i=>pilot.enqueue('claim',i)};}
