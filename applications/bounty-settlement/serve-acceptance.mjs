// Explicit genuine-evidence service entry. No signing, funding or deployment.
import { openSync, closeSync, readFileSync, fstatSync, lstatSync, constants } from 'node:fs';
import { dirname, resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Store, exact, need, sha } from '../bounty-demo/core.mjs';
import {taskChainReader} from './chain-service.mjs';
import { createAcceptanceApplication } from './acceptance-service.mjs';
const MAX_FILE=256*1024*1024, MAX_TOTAL=1024*1024*1024;
const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
function ancestors(path){
  need(isAbsolute(path)&&resolve(path)===path,'absolute normalized operator path required');
  for(let p=dirname(path);;p=dirname(p)){
    const s=lstatSync(p);need(s.isDirectory()&&!s.isSymbolicLink(),'operator path ancestor must be a directory');
    need((s.mode&0o022)===0,'operator path ancestry must not be writable by others');
    if(p==='/')break;
  }
}
export function readPinned(d,{privateFile=false,budget}={}){
  exact(d,['path','bytes','sha256']);need(Number.isSafeInteger(d.bytes)&&d.bytes>=0&&d.bytes<=MAX_FILE&&hash(d.sha256),'invalid operator file descriptor');
  ancestors(d.path);const fd=openSync(d.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const s=fstatSync(fd);need(s.isFile()&&s.nlink===1&&s.size===d.bytes&&(s.mode&0o022)===0,'operator file must be regular, unaliased and immutable to others');
    if(privateFile)need(s.uid===process.getuid()&&(s.mode&0o077)===0,'operator secret must be private and owned');
    if(budget){budget.bytes+=d.bytes;need(budget.bytes<=MAX_TOTAL,'evidence snapshot exceeds service bound');}
    const b=readFileSync(fd);need(b.length===d.bytes&&sha(b)===d.sha256,'operator file pin mismatch');return b;
  }finally{closeSync(fd);}
}
export function readEvidence(snapshot){
  const budget={bytes:0}, doc=JSON.parse(readPinned(snapshot,{budget}));
  exact(doc,['schema','request','results','originals']);need(doc.schema==='dsmack-bounty-original-evidence-files/1'&&Array.isArray(doc.originals)&&doc.originals.length===10,'closed ten-stage file snapshot required');
  return {requestBytes:readPinned(doc.request,{budget}),resultsBytes:readPinned(doc.results,{budget}),originals:doc.originals.map(s=>{
    exact(s,['stage_id','report','receipt','manifest','public_inputs','outputs']);
    need(s.outputs&&Object.getPrototypeOf(s.outputs)===Object.prototype&&Object.keys(s.outputs).length<=66,'bounded output file map required');
    return {stage_id:s.stage_id,reportBytes:readPinned(s.report,{budget}),receiptBytes:readPinned(s.receipt,{budget}),manifestBytes:readPinned(s.manifest,{budget}),publicInputsBytes:readPinned(s.public_inputs,{budget}),outputs:Object.fromEntries(Object.entries(s.outputs).map(([k,v])=>[k,readPinned(v,{budget})]))};
  })};
}
export function startAcceptance(configBytes){
  const c=JSON.parse(configBytes);exact(c,['schema','state_path','operator_token','verifier_keys','report_keys','admissions','evidence','repositories','port'],['chain_selections','task_annotations']);
  need(c.schema==='dsmack-bounty-acceptance-service/1','wrong service domain');
  need(Number.isSafeInteger(c.port)&&c.port>0&&c.port<65536,'invalid service port');
  need(Array.isArray(c.repositories)&&c.repositories.length>0&&c.repositories.every(x=>typeof x==='string'),'explicit repositories required');
  need(c.evidence&&Object.getPrototypeOf(c.evidence)===Object.prototype,'operator evidence map required');
  need(Object.keys(c.evidence).every(id=>/^[a-f0-9]{32}$/.test(id)&&Object.hasOwn(c.admissions,id)),'evidence must belong to admitted attempts');
  ancestors(c.state_path);
  const parent=lstatSync(dirname(c.state_path));need(parent.uid===process.getuid()&&(parent.mode&0o077)===0,'state directory must be private and owned');
  try{const s=lstatSync(c.state_path);need(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.uid===process.getuid()&&(s.mode&0o077)===0,'existing state must be private regular owned file');}catch(e){if(e.code!=='ENOENT')throw e;}
  const token=readPinned(c.operator_token,{privateFile:true}).toString('utf8').trim();
  try{const fd=openSync(c.state_path,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);closeSync(fd);}catch(e){if(e.code!=='EEXIST')throw e;}
  const store=new Store(c.state_path,{verifierKeys:c.verifier_keys,allowedRepositories:c.repositories});let server;
  try{server=createAcceptanceApplication({store,operatorToken:token,admissions:c.admissions,reportKeys:c.report_keys,allowedRepositories:c.repositories,taskAnnotations:c.task_annotations??[],chainObservation:c.chain_selections?taskChainReader(store,c.chain_selections):undefined,loadInput:async id=>{need(Object.hasOwn(c.evidence,id),'original evidence not staged',409);return readEvidence(c.evidence[id]);}});}
  catch(e){store.close();throw e;}
  return {server,store,port:c.port};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    need(process.argv.length===5,'usage: node serve-acceptance.mjs CONFIG BYTES SHA256');
    const bytes=readPinned({path:process.argv[2],bytes:Number(process.argv[3]),sha256:process.argv[4]});
    const {server,store,port}=startAcceptance(bytes);
    server.listen(port,'127.0.0.1',()=>console.log('Original-evidence acceptance service listening on loopback port '+port));
    const stop=()=>server.close(()=>{store.close();process.exit(0);});process.on('SIGTERM',stop);process.on('SIGINT',stop);
    server.on('error',()=>{store.close();console.error('Acceptance service listener failed');process.exitCode=1;});
  }catch{console.error('Acceptance service refused its operator configuration');process.exitCode=2;}
}
