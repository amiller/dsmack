import {createPublicKey,verify,createHash} from 'node:crypto';
import {constants as C,openSync,closeSync,fstatSync,readSync,lstatSync,readdirSync,realpathSync} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
const authenticatedHandles=new WeakSet();
const authorityKeys=new WeakMap();
function deepFreeze(o){if(o&&typeof o==='object'){for(const v of Object.values(o))deepFreeze(v);Object.freeze(o);}return o;}
function need(ok,message){if(!ok)throw Error(message);}
function keys(o,list){need(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===[...list].sort().join('|'),'Inventory fields mismatch');}
function text(s,n=256){need(typeof s==='string'&&s.length>0&&s.length<=n&&!/[\x00-\x1f]/.test(s),'Invalid inventory string');}
function sha(s){need(typeof s==='string'&&/^[a-f0-9]{64}$/.test(s),'Invalid digest');}
function integer(n,max){need(Number.isSafeInteger(n)&&n>=0&&n<=max,'Invalid integer');}
export function canonical(o){if(o===null||typeof o!=='object')return JSON.stringify(o);if(Array.isArray(o))return '['+o.map(canonical).join(',')+']';return '{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}';}
export function authenticateInventory(raw,signature,{publicKey,keyId,channel,minSequence,now=Date.now()}={}){
 need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=262144,'Inventory byte limit');
 need(Buffer.isBuffer(signature)&&signature.length===64,'Detached signature required');
 const key=createPublicKey(publicKey);need(key.asymmetricKeyType==='ed25519','Ed25519 external trust root required');
 const v=JSON.parse(raw.toString('utf8'));need(raw.toString('utf8')===canonical(v),'Canonical inventory required');
 need(['dsmack-alpha-release/1','dsmack-alpha-release/2'].includes(v.schema),'Unknown release schema');
 need(verify(null,Buffer.concat([Buffer.from(v.schema+'\0'),raw]),key,signature),'Release signature refused');
 keys(v,['schema','key_id','release_id','channel','sequence','issued_at','expires_at','platform','app','files','profiles','provenance_sha256','verification_policy',...(v.schema==='dsmack-alpha-release/2'?['archive']:[])]);
 if(v.schema==='dsmack-alpha-release/2'){keys(v.archive,['format','bytes','sha256']);need(['tar','tar+gzip'].includes(v.archive.format),'Archive format');integer(v.archive.bytes,34359738368);sha(v.archive.sha256);}
 need(v.key_id===keyId&&v.channel===channel,'Release authority or channel mismatch');
 text(v.release_id);integer(v.sequence,Number.MAX_SAFE_INTEGER);integer(minSequence,Number.MAX_SAFE_INTEGER);need(v.sequence>=minSequence,'Release rollback refused');
 for(const k of ['issued_at','expires_at'])need(typeof v[k]==='string'&&new Date(v[k]).toISOString()===v[k],'Invalid release timestamp');
 need(Number.isFinite(now)&&Date.parse(v.issued_at)<=now&&now<Date.parse(v.expires_at)&&Date.parse(v.expires_at)>Date.parse(v.issued_at),'Release not current');
 keys(v.platform,['os','arch','minimum_version']);need(v.platform.os==='darwin'&&v.platform.arch==='arm64','Unsupported platform');text(v.platform.minimum_version,32);
 const notaryKey=v.schema==='dsmack-alpha-release/2'?'notarization_evidence_sha256':'notarization_ticket_sha256';
 keys(v.app,['team_id','bundle_id','cdhash_full','certificate_sha256','attestation_category','entitlements_sha256',notaryKey]);
 need(v.app.attestation_category===6,'Developer ID category 6 required');text(v.app.team_id,32);text(v.app.bundle_id);for(const k of ['cdhash_full','certificate_sha256','entitlements_sha256',notaryKey])sha(v.app[k]);
 sha(v.provenance_sha256);text(v.verification_policy);
 need(Array.isArray(v.files)&&v.files.length>0&&v.files.length<=4096,'Invalid file closure');
 let total=0;const paths=new Set();for(const f of v.files){keys(f,['path','bytes','sha256','mode']);text(f.path,512);need(!f.path.startsWith('/')&&f.path.split('/').every(x=>x&&x!=='.'&&x!=='..')&&!f.path.includes('\\'),'Unsafe member path');need(!paths.has(f.path),'Duplicate member');paths.add(f.path);integer(f.bytes,8589934592);total+=f.bytes;need(Number.isSafeInteger(total)&&total<=34359738368,'Release total size limit');sha(f.sha256);need(f.mode===0o600||f.mode===0o700,'Unsupported member mode');}
 if(v.schema==='dsmack-alpha-release/2'){const aliases=new Map();for(const path of paths){need(/^[A-Za-z0-9._/-]+$/.test(path),'ASCII release paths required');const parts=path.split('/');for(let n=1;n<=parts.length;n++){const prefix=parts.slice(0,n).join('/'),alias=prefix.toLowerCase();need(!aliases.has(alias)||aliases.get(alias)===prefix,'Filesystem path alias');aliases.set(alias,prefix);}}}
 for(const path of paths){const parts=path.split('/');while(parts.length>1){parts.pop();need(!paths.has(parts.join('/')),'Ancestor-file conflict');}}
 need(Array.isArray(v.profiles)&&v.profiles.length>0&&v.profiles.length<=32,'Invalid profiles');const ids=new Set();for(const p of v.profiles){keys(p,['profile_id','descriptor_path','descriptor_sha256']);text(p.profile_id);need(!ids.has(p.profile_id),'Duplicate profile');ids.add(p.profile_id);sha(p.descriptor_sha256);need(v.files.some(f=>f.path===p.descriptor_path&&f.sha256===p.descriptor_sha256),'Profile not in exact closure');}
 const result=Object.freeze({inventory:deepFreeze(v),inventory_sha256:createHash('sha256').update(raw).digest('hex'),signature_authenticated:true,apple_signature_checked:false,notarization_checked:false,enrolled:false,launch_ready:false});authenticatedHandles.add(result);authorityKeys.set(result,key.export({format:"der",type:"spki"}).toString("hex"));return result;
}
export function verifyStagedFiles(root,authenticated){
 need(authenticatedHandles.has(authenticated),'Original authenticated handle required');root=resolve(root);need(realpathSync(root)===root,'Symlink staging ancestry refused');for(let a=root;;a=dirname(a)){const s=lstatSync(a);need(s.isDirectory()&&[0,process.getuid()].includes(s.uid)&&(s.mode&0o022)===0,'Unprotected staging ancestry');if(a===dirname(a))break;}
 const expected=new Map(authenticated.inventory.files.map(f=>[f.path,f]));const seen=[];
 function walk(dir,relative=''){const st=lstatSync(dir);need(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&(st.mode&0o077)===0,'Owned private staging directory required');for(const name of readdirSync(dir)){const rel=relative?relative+'/'+name:name;const path=join(dir,name);const s=lstatSync(path);if(s.isDirectory()){walk(path,rel);continue;}need(s.isFile()&&!s.isSymbolicLink(),'Nonregular staged member');const e=expected.get(rel);need(e,'Unlisted staged member');const fd=openSync(path,C.O_RDONLY|C.O_NOFOLLOW|C.O_NONBLOCK);try{const a=fstatSync(fd);need(a.isFile()&&a.uid===process.getuid()&&a.nlink===1&&(a.mode&0o777)===e.mode&&a.size===e.bytes,'Staged member metadata mismatch');const hash=createHash('sha256');const buffer=Buffer.alloc(1024*1024);let offset=0;while(offset<a.size){const n=readSync(fd,buffer,0,Math.min(buffer.length,a.size-offset),offset);need(n>0,'Short staged read');hash.update(buffer.subarray(0,n));offset+=n;}need(hash.digest('hex')===e.sha256,'Staged member digest mismatch');const b=fstatSync(fd);need(a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs,'Member changed during check');}finally{closeSync(fd);}seen.push(rel);}}
 walk(root);need(seen.length===expected.size,'Missing staged member');return {...authenticated,staged_files_checked:true,launch_ready:false};
}

// Task authorization is separate from the reusable release signature.
export function authenticateWorkload(raw,signature,authenticated,profile,{publicKey,now=Date.now()}={}){
 need(authenticatedHandles.has(authenticated),'Original authenticated release handle required');
 need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=65536&&Buffer.isBuffer(signature)&&signature.length===64,'Workload admission bounds');
 const v=JSON.parse(raw.toString('utf8'));need(canonical(v)===raw.toString('utf8'),'Canonical workload admission');
 keys(v,['schema','key_id','release_inventory_sha256','profile_id','compose_manifest_sha256','attempt_id','closure_context_sha256','workload_disk','issued_at','expires_at']);
 need(v.schema==='dsmack-alpha-workload-admission/1','Workload admission schema');
 const key=createPublicKey(publicKey);need(key.asymmetricKeyType==='ed25519'&&key.export({format:'der',type:'spki'}).toString('hex')===authorityKeys.get(authenticated)&&verify(null,Buffer.concat([Buffer.from(v.schema+'\0'),raw]),key,signature),'Workload signature/authority refused');
 need(v.key_id===authenticated.inventory.key_id&&v.release_inventory_sha256===authenticated.inventory_sha256&&v.profile_id===profile.profile_id&&v.compose_manifest_sha256===profile.execution_profile.compose_manifest_sha256,'Workload release/profile/manifest mismatch');
 need(['dsmack-alpha-profile/2','dsmack-alpha-profile/3'].includes(profile.schema)&&/^[a-f0-9]{32}$/.test(v.attempt_id),'Workload attempt/profile');sha(v.closure_context_sha256);
 keys(v.workload_disk,['bytes','sha256']);integer(v.workload_disk.bytes,4294967296);need(v.workload_disk.bytes>0,'Empty workload');sha(v.workload_disk.sha256);
 for(const k of ['issued_at','expires_at'])need(typeof v[k]==='string'&&new Date(v[k]).toISOString()===v[k],'Workload timestamp');
 need(Date.parse(v.issued_at)<=now&&now<Date.parse(v.expires_at)&&Date.parse(v.expires_at)>Date.parse(v.issued_at)&&Date.parse(v.expires_at)<=Date.parse(authenticated.inventory.expires_at),'Workload not current');
 return deepFreeze(v);
}
