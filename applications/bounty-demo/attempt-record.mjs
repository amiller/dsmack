import { constants as C, openSync, closeSync, fstatSync, readSync, writeSync, fsyncSync, renameSync, unlinkSync } from 'node:fs';
import { dirname, resolve, basename, join } from 'node:path';
import { randomBytes } from 'node:crypto';
const fail=()=>{throw Error('Invalid or unsafe saved attempt record');};
export function serverURL(value){const u=new URL(value);if(u.username||u.password||u.search||u.hash||u.pathname!=='/'||!(u.protocol==='https:'||(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname))))fail();return u.origin;}
export function validateRecord(v, expectedServer){
  const keys=['schema','state','server','task_id','worker','payee','request_id','capability'];
  if(!v||typeof v!=='object'||Array.isArray(v)||keys.some(k=>!Object.hasOwn(v,k))||Object.keys(v).some(k=>!keys.includes(k)&&k!=='attempt_id'))fail();
  if(v.schema!=='dsmack-bounty-attempt/1'||!['claim-requested','claimed'].includes(v.state)||serverURL(v.server)!==v.server||expectedServer&&v.server!==serverURL(expectedServer))fail();
  if(['task_id','worker','payee','request_id','capability'].some(k=>typeof v[k]!=='string')||!/^[a-z0-9-]{1,80}$/.test(v.task_id)||typeof v.worker!=='string'||!v.worker.length||v.worker.length>80||/[\x00-\x1f\x7f]/.test(v.worker)||!/^0x[0-9a-f]{40}$/.test(v.payee)||!/^[a-f0-9]{64}$/.test(v.request_id)||typeof v.capability!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(v.capability)||Buffer.from(v.capability,'base64url').toString('base64url')!==v.capability)fail();
  if(v.state==='claimed'?!/^[a-f0-9]{32}$/.test(v.attempt_id):Object.hasOwn(v,'attempt_id'))fail();return v;
}
function checked(fd,dir=false){const s=fstatSync(fd);if(s.uid!==process.getuid()||(s.mode&0o077)!==0||(dir?!s.isDirectory():!s.isFile()||s.nlink!==1||s.size>16384))fail();return s;}
export function readRecord(path,server){const fd=openSync(path,C.O_RDONLY|C.O_NOFOLLOW|C.O_NONBLOCK);try{checked(fd);const buffer=Buffer.alloc(16385);let n=0;while(n<buffer.length){const got=readSync(fd,buffer,n,buffer.length-n,null);if(!got)break;n+=got;}if(n>16384)fail();const b=buffer.subarray(0,n);try{return validateRecord(JSON.parse(b.toString('utf8')),server);}catch{fail();}}finally{closeSync(fd);}}
export function writeRecord(path,value,{replace=false,expected}={}){
  validateRecord(value);path=resolve(path);const parent=dirname(path);const d=openSync(parent,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);let temp;
  try{checked(d,true);if(replace){const old=readRecord(path,value.server);if(!expected||JSON.stringify(old)!==JSON.stringify(expected))fail();}
    temp=replace?join(parent,'.'+basename(path)+'.'+randomBytes(16).toString('hex')):path;
    const fd=openSync(temp,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);try{const data=Buffer.from(JSON.stringify(value)+'\n');let n=0;while(n<data.length)n+=writeSync(fd,data,n,data.length-n);fsyncSync(fd);}finally{closeSync(fd);}
    if(replace)renameSync(temp,path);temp=undefined;fsyncSync(d);
  }finally{if(temp&&replace){try{unlinkSync(temp);}catch{}}closeSync(d);}
}
export function newRecord({server,task_id,worker,payee}){return validateRecord({schema:'dsmack-bounty-attempt/1',state:'claim-requested',server:serverURL(server),task_id,worker,payee:payee.toLowerCase(),request_id:randomBytes(32).toString('hex'),capability:randomBytes(32).toString('base64url')});}
