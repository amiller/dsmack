import { readFileSync, existsSync } from 'node:fs';
import { readRecord, writeRecord, newRecord, serverURL } from './attempt-record.mjs';
const [command,...args]=process.argv.slice(2);
if(command==='help'||!command){console.log(`Node 24+: node cli.mjs <command>\n  tasks\n  show TASK\n  create TASK_JSON\n  claim TASK WORKER PAYEE --out PRIVATE_RECORD\n  progress --attempt-file PRIVATE_RECORD EVENT_JSON\n  submit --attempt-file PRIVATE_RECORD SUBMISSION_JSON\n  progress ATTEMPT EVENT_JSON\n  submit ATTEMPT SUBMISSION_JSON\n  verdict ATTEMPT CERTIFICATE_JSON\nBOUNTY_URL defaults to http://127.0.0.1:8787.\nBOUNTY_TOKEN_FILE supplies operator authorization for claim/create/verdict.\nClaim saves a capability BEFORE contacting the server. Retry the same command and file after a lost response.\nRecord parent directory must be owned and private (0700). Never share or commit this file.\nSaved records authorize progress/submit without another token file. Browser can open a claimed record locally.`);process.exit(0);}
const root=serverURL(process.env.BOUNTY_URL??'http://127.0.0.1:8787');
const json=p=>JSON.parse(readFileSync(p,'utf8'));let path,body,record,recordPath;
const id=s=>{if(typeof s!=='string'||!/^[a-z0-9-]{1,80}$/.test(s))throw Error('invalid id');return s;};
switch(command){
case'tasks':path='/api/tasks';break;
case'show':path='/api/tasks/'+id(args[0]);break;
case'create':path='/api/tasks';body=json(args[0]);break;
case'claim':{
  if(args.length!==5||args[3]!=='--out')throw Error('claim requires TASK WORKER PAYEE --out PRIVATE_RECORD');recordPath=args[4];
  if(existsSync(recordPath)){record=readRecord(recordPath,root);if(record.task_id!==args[0]||record.worker!==args[1]||record.payee!==args[2].toLowerCase())throw Error('Saved claim terms conflict');}
  else{record=newRecord({server:root,task_id:args[0],worker:args[1],payee:args[2]});writeRecord(recordPath,record);}
  path='/api/tasks/'+id(record.task_id)+'/claim';body={worker:record.worker,payee:record.payee,request_id:record.request_id,capability:record.capability};break;
}
case'progress':case'submit':case'verdict':{
  if(args[0]==='--attempt-file'){if(command==='verdict'||args.length!==3)throw Error('Unsupported saved-record command');record=readRecord(args[1],root);if(record.state!=='claimed')throw Error('Retry claim to resolve saved request first');path='/api/attempts/'+id(record.attempt_id)+'/'+command;body=json(args[2]);}
  else{path='/api/attempts/'+id(args[0])+'/'+command;body=json(args[1]);}break;
}
default:throw Error('unknown command');}
let token;if(body){if(record&&command!=='claim')token=record.capability;else{if(!process.env.BOUNTY_TOKEN_FILE)throw Error('BOUNTY_TOKEN_FILE required');token=readFileSync(process.env.BOUNTY_TOKEN_FILE,'utf8').trim();}}
try{
  const r=await fetch(new URL(path,root),{method:body?'POST':'GET',redirect:'error',signal:AbortSignal.timeout(15000),headers:{...(body?{'Content-Type':'application/json',Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});const result=await r.json();
  if(command==='claim'&&r.ok){const a=result.attempt;if(!a||!/^[a-f0-9]{32}$/.test(a.id)||a.task_id!==record.task_id||a.worker!==record.worker||a.payee!==record.payee||result.token!==record.capability||record.attempt_id&&record.attempt_id!==a.id)throw Error('Claim response binding mismatch');const updated={...record,state:'claimed',attempt_id:a.id};writeRecord(recordPath,updated,{replace:true,expected:record});console.log(JSON.stringify({attempt:a,saved:true}));}
  else{console.log(JSON.stringify(result,null,2));if(!r.ok)process.exitCode=1;}
}catch{console.error(command==='claim'?'Claim outcome uncertain; preserve the private record and retry the same command.':'Request failed; private credentials withheld.');process.exitCode=1;}
