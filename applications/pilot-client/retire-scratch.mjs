// Optional host storage retirement; never a task verifier, launcher or secure erase.
import {constants as C,lstatSync,readFileSync,openSync,closeSync,writeSync,fsyncSync,readdirSync,unlinkSync,existsSync} from 'node:fs';
import {resolve,dirname,basename,join} from 'node:path';
import {homedir} from 'node:os';
import {createPublicKey,verify,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
class RetirementRefusal extends Error {}
const fail=m=>{throw new RetirementRefusal(m);},need=(v,m)=>{if(!v)fail(m);};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join('\0')===[...k].sort().join('\0'),'closed fields');
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v!==null&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const sha=b=>createHash('sha256').update(b).digest('hex');
const TARGETS=['scratch.img','scratch-template.img.staged'];
function protectedPath(path){need(resolve(path)===path,'normalized absolute path');for(let p=path;;p=dirname(p)){const s=lstatSync(p);need(!s.isSymbolicLink()&&!(s.mode&0o022),'protected path');if(p==='/')break;}}
function readPublic(d,cap){exact(d,['path','bytes','sha256']);need(Number.isSafeInteger(d.bytes)&&d.bytes>0&&d.bytes<=cap&&/^[a-f0-9]{64}$/.test(d.sha256),'public descriptor');protectedPath(d.path);const s=lstatSync(d.path);need(s.isFile()&&s.nlink===1&&s.size===d.bytes,'public regular file');const fd=openSync(d.path,C.O_RDONLY|C.O_NOFOLLOW|C.O_NONBLOCK);try{const b=readFileSync(fd);need(b.length===d.bytes&&sha(b)===d.sha256,'public pin');return b;}finally{closeSync(fd);}}
function directory(path){protectedPath(path);const s=lstatSync(path);need(s.isDirectory()&&s.uid===process.getuid()&&(s.mode&0o777)===0o700,'owned0700 directory');}
function metadata(path){const s=lstatSync(path,{bigint:true});need(s.isFile()&&s.nlink===1n&&s.uid===BigInt(process.getuid())&&!(Number(s.mode)&0o077),'owned private regular single-link scratch');return {dev:String(s.dev),ino:String(s.ino),bytes:Number(s.size),mode:Number(s.mode&0o777n),mtime_ns:String(s.mtimeNs),ctime_ns:String(s.ctimeNs)};}
function absent(path){try{lstatSync(path);return false;}catch(e){if(e.code==='ENOENT')return true;throw e;}}
function processGone(pid){need(Number.isSafeInteger(pid)&&pid>0,'positive native process ID');try{process.kill(pid,0);fail('native process remains');}catch(e){if(e.code!=='ESRCH')throw e;}}
function noOpenReferences(paths){if(!paths.length)return;const tool=process.platform==='darwin'?'/usr/sbin/lsof':process.platform==='linux'?'/usr/bin/lsof':null;need(tool,'supported host');const p=spawnSync(tool,['-w','-Fpf','--',...paths],{encoding:'utf8',timeout:15000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin',HOME:'/nonexistent'}});need(!p.error&&p.status===1&&p.stdout===''&&p.stderr==='','scratch has open references or probe unavailable');}
function durable(fd,row,dir){writeSync(fd,canonical(row)+'\n');fsyncSync(fd);const d=openSync(dir,C.O_RDONLY|C.O_DIRECTORY);try{fsyncSync(d);}finally{closeSync(d);}}
function authenticate(s){
 const closure=JSON.parse(readPublic(s.closure,8192)),context=JSON.parse(readPublic(s.checker_context,65536)),report=JSON.parse(readPublic(s.report,131072)),q=JSON.parse(readPublic(s.quiescence,16384));
 exact(closure,['schema','attempt_id','selectors']);need(closure.schema==='dsmack-result-closure-context/1'&&closure.attempt_id===s.run_id&&Array.isArray(closure.selectors)&&closure.selectors.length===1&&closure.selectors[0]===context.subject.receipt_selector,'prelaunch closure/selector');
 need(context.subject.receipt_environment==='vm'&&report.runresult_report_version===2&&report.verified===true&&report.subject.outputs_verified===true&&report.subject.evidence_class==='apple-hardware-assertion'&&report.apple.assertion_counters_authenticated===true&&report.apple.environment==='production','original full-proof completion');
 for(const k of ['verifier','verifier_context'])need(canonical(report[k])===canonical(context[k]),'selected verifier context');
 for(const [k,v] of Object.entries(context.subject))need(canonical(report.subject[k])===canonical(v),'selected proof subject');
 need(Number.isSafeInteger(report.subject.launch_counter)&&Number.isSafeInteger(report.subject.result_counter)&&report.subject.result_counter>report.subject.launch_counter&&report.apple.receipt_status==='retained_not_validated','authenticated completed counter order');
 exact(s.report_key,['key_id','public_key_b64']);const sig=report.report_sig;exact(sig,['alg','key_id','sig_b64']);need(sig.alg==='ed25519'&&sig.key_id===s.report_key.key_id&&report.verifier.key_id===s.report_key.key_id,'selected public report authority');
 const key=Buffer.from(s.report_key.public_key_b64,'base64'),signature=Buffer.from(sig.sig_b64,'base64');need(key.length===32&&key.toString('base64')===s.report_key.public_key_b64&&signature.length===64&&signature.toString('base64')===sig.sig_b64,'canonical public signature');
 const payload={...report};delete payload.report_sig;const spki=Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key]);need(verify(null,Buffer.from(canonical(payload)),createPublicKey({key:spki,format:'der',type:'spki'}),signature),'original report signature');
 exact(q,['schema','run_id','attempt_dir','native_pids']);need(q.schema==='dsmack-native-quiescence/1'&&q.run_id===s.run_id&&q.attempt_dir===s.attempt_dir&&Array.isArray(q.native_pids)&&q.native_pids.length>0&&q.native_pids.length<=16,'selected native quiescence');q.native_pids.forEach(processGone);
 return q;
}
function retireExclusive(selectionPath,expectedSha){
 need(/^[a-f0-9]{64}$/.test(expectedSha),'independent selection hash');protectedPath(selectionPath);const raw=readFileSync(selectionPath);need(raw.length<=65536&&sha(raw)===expectedSha,'selected cleanup bytes');const s=JSON.parse(raw);exact(s,['schema','run_id','attempt_dir','closure','checker_context','report','report_key','quiescence','public_template']);need(s.schema==='dsmack-scratch-retirement/1'&&/^[a-f0-9]{32}$/.test(s.run_id),'closed retirement selection');
 need(s.attempt_dir.startsWith(homedir()+'/')&&basename(s.attempt_dir)==='attempt-'+s.run_id,'pinned prelaunch attempt directory');directory(dirname(s.attempt_dir));directory(s.attempt_dir);
 exact(s.public_template,['bytes','sha256']);need([1073741824,4294967296].includes(s.public_template.bytes)&&/^[a-f0-9]{64}$/.test(s.public_template.sha256),'independently selected public template pin');
 const q=authenticate(s),journal=join(dirname(s.attempt_dir),'.scratch-retirement-'+s.run_id+'.jsonl');let fd,rows;
 if(absent(journal)){
  const targets=TARGETS.map(name=>({name,metadata:metadata(join(s.attempt_dir,name))}));need(targets.every(x=>x.metadata.bytes===s.public_template.bytes),'selected scratch capacity');noOpenReferences(targets.map(x=>join(s.attempt_dir,x.name)));
  fd=openSync(journal,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);const intent={schema:'dsmack-scratch-retirement-journal/1',event:'intent',selection_sha256:expectedSha,run_id:s.run_id,targets};durable(fd,intent,dirname(journal));rows=[intent];
 }else{
  protectedPath(journal);const st=lstatSync(journal);need(st.isFile()&&st.nlink===1&&st.uid===process.getuid()&&(st.mode&0o777)===0o600&&st.size<=65536,'owned bounded journal');const data=readFileSync(journal,'utf8');need(data.endsWith('\n'),'complete retirement journal');rows=data.trimEnd().split('\n').map(x=>JSON.parse(x));const first=rows[0];need(first.schema==='dsmack-scratch-retirement-journal/1'&&first.event==='intent'&&first.selection_sha256===expectedSha&&first.run_id===s.run_id&&canonical(first.targets.map(x=>x.name))===canonical(TARGETS),'same selected retirement intent');need(rows.every((x,i)=>i===0||['removed','absent-after-intent','complete'].includes(x.event)),'known retirement events');fd=openSync(journal,C.O_WRONLY|C.O_APPEND|C.O_NOFOLLOW);
 }
 try{
  if(rows.some(x=>x.event==='complete')){need(TARGETS.every(n=>absent(join(s.attempt_dir,n))),'retired scratch reappeared');return {status:'already-retired',files:2,secure_erase_claim:false,mutable_content_read:false};}
  for(const row of rows[0].targets){q.native_pids.forEach(processGone);const p=join(s.attempt_dir,row.name);if(absent(p)){durable(fd,{event:'absent-after-intent',name:row.name},dirname(journal));continue;}
   need(canonical(metadata(p))===canonical(row.metadata),'scratch identity changed after intent');noOpenReferences([p]);need(canonical(metadata(p))===canonical(row.metadata),'scratch changed before unlink');unlinkSync(p);const d=openSync(s.attempt_dir,C.O_RDONLY|C.O_DIRECTORY);try{fsyncSync(d);}finally{closeSync(d);}durable(fd,{event:'removed',name:row.name},dirname(journal));
  }
  durable(fd,{event:'complete'},dirname(journal));return {status:'retired',files:2,secure_erase_claim:false,mutable_content_read:false,public_template_content_rehashed:false,retired_logical_bytes:2*s.public_template.bytes};
 }finally{closeSync(fd);}
}
export function retire(selectionPath,expectedSha){
 need(/^[a-f0-9]{64}$/.test(expectedSha),'independent selection hash');protectedPath(selectionPath);
 const st=lstatSync(selectionPath);need(st.isFile()&&st.nlink===1&&st.uid===process.getuid()&&st.size<=65536&&!(st.mode&0o077),'owned bounded selection');
 const raw=readFileSync(selectionPath);need(sha(raw)===expectedSha,'selected cleanup bytes');const s=JSON.parse(raw);
 need(typeof s.run_id==='string'&&/^[a-f0-9]{32}$/.test(s.run_id)&&typeof s.attempt_dir==='string'&&basename(s.attempt_dir)==='attempt-'+s.run_id,'selected attempt');directory(dirname(s.attempt_dir));directory(s.attempt_dir);
 const lock=join(dirname(s.attempt_dir),'.scratch-retirement-'+s.run_id+'.lock');
 const fd=openSync(lock,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);const identity=lstatSync(lock,{bigint:true});
 try{durable(fd,{schema:'dsmack-scratch-retirement-lock/1',selection_sha256:expectedSha,pid:process.pid},dirname(lock));return retireExclusive(selectionPath,expectedSha);}
 finally{closeSync(fd);const current=lstatSync(lock,{bigint:true});need(current.dev===identity.dev&&current.ino===identity.ino,'exclusive lock changed');unlinkSync(lock);const d=openSync(dirname(lock),C.O_RDONLY|C.O_DIRECTORY);try{fsyncSync(d);}finally{closeSync(d);}}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){try{need(process.argv.length===4,'selection path and independent SHA required');console.log(JSON.stringify(retire(process.argv[2],process.argv[3])));}catch(error){const reason=error instanceof RetirementRefusal?error.message.slice(0,192):'filesystem or subprocess check failed';console.error('Scratch retirement refused: '+reason+'. Preserve evidence/journal; no automatic retry or secure erase implied.');process.exitCode=2;}}
