import {createServer} from 'node:http';
import {readFileSync,statSync,createReadStream} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join,dirname} from 'node:path';
import {Pilot,need,Refusal,sha} from './core.mjs';
import {remoteAdapters,walletVerifier} from './adapters.mjs';
const workerAuth=(req,hash)=>{const t=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization??'')?.[1];need(t&&sha(t)===hash,'worker authorization required',401);};
const WEB=join(dirname(fileURLToPath(import.meta.url)),'../web');
export function server(pilot,{basePath='',maxConnections=64,workerTokenHash}={}){
 const rates=new Map();
 const s=createServer(async(req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; script-src 'self'; frame-ancestors 'none'");
  try{
   const url=new URL(req.url,'http://local');need(!url.search,'query parameters refused');need(url.pathname===basePath||url.pathname.startsWith(basePath+'/'),'route not found',404);const path=url.pathname.slice(basePath.length)||'/';const method=req.method;
   if(method==='GET'&&['/','/index.html','/app.mjs','/style.css'].includes(path)){const name=path==='/'?'index.html':path.slice(1);res.setHeader('Content-Type',name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.mjs')?'text/javascript':'text/css');res.end(readFileSync(join(WEB,name)));return;}
   if(method==='GET'&&path==='/agent.json'){return send(res,{schema:'dsmack-arcade-agent-entry/1',task:'api/task',authorization:'api/authorization-challenges',attempts:'api/attempts',runner_source:'https://github.com/amiller/dsmack',wallet_keys_uploaded:false,settlement:'Base Sepolia WorkEscrow trusted EOA bridge'});}
   if(method==='GET'&&path==='/api/task')return send(res,pilot.task);
   const reg=/^\/api\/registrations\/([a-f0-9]{32})$/.exec(path);if(method==='GET'&&reg){const r=pilot.get('registration',reg[1]);return send(res,{registration_id:r.id,state:r.state,enrollment:r.enrollment,pending_job_id:r.pending_job_id??null});}
   if(method==='POST'&&path==='/api/nodes/lease'){const raw=await body(req,4096);const v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));const cap=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization??'')?.[1];const lease=pilot.nodeLease(v,cap);if(!lease){res.writeHead(204);res.end();return;}return send(res,lease);}
   const wm=/^\/api\/worker\/(lease|jobs\/([a-f0-9]{32})\/(result|files|artifacts)(?:\/([^/]+))?)$/.exec(path);
   if(wm){workerAuth(req,workerTokenHash);if(method==='GET'&&wm[3]==='files'&&wm[4])return file(req,res,pilot.jobFile(wm[2],decodeURIComponent(wm[4])));const raw=await body(req,method==='PUT'?4194304:524288);let v;if(method!=='PUT'){try{v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}catch{throw new Refusal('invalid worker JSON');}}if(method==='POST'&&wm[1]==='lease'){const leased=pilot.lease(v);if(!leased){res.writeHead(204);res.end();return;}return send(res,leased);}if(method==='POST'&&wm[3]==='result')return send(res,pilot.jobResult(wm[2],v));if(method==='POST'&&wm[3]==='artifacts'&&!wm[4])return send(res,pilot.artifactManifest(wm[2],v));if(method==='PUT'&&wm[3]==='artifacts'&&wm[4])return send(res,pilot.artifactChunk(wm[2],decodeURIComponent(wm[4]),req.headers['content-range'],raw));throw new Refusal('worker route not found',404);}
   const artifact=/^\/api\/artifacts\/([a-f0-9]{32})\/([^/]+)$/.exec(path);if(method==='GET'&&artifact)return file(req,res,pilot.artifactFile(artifact[1],decodeURIComponent(artifact[2])));
   const m=/^\/api\/attempts\/([a-f0-9]{32})(?:\/(execution|evidence|claim)(?:\/([a-f0-9]{32})(?:\/([^/]+))?)?)?$/.exec(path);
   if(method==='GET'&&m&&!m[2])return send(res,pilot.publicAttempt(pilot.get('attempt',m[1])));
   if(method==='GET'&&m&&m[2]==='claim')return send(res,await pilot.claim(m[1]));
   // Same-origin browser writes only; CLI may omit Origin. No CORS privilege.
   need(!req.headers.origin||req.headers.origin===pilot.origin,'origin refused',403);
   const remote=req.socket.remoteAddress??'unknown',now=Date.now();if(rates.size>10000)rates.clear();let rate=rates.get(remote);if(!rate||now-rate.start>60000)rates.set(remote,rate={start:now,n:0});need(++rate.n<=240,'rate limit',429);
   const cap=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization??'')?.[1];
   const chunk=method==='PUT'&&m?.[2]==='evidence'&&m[3]&&m[4];const raw=await body(req,chunk?4194304:524288);let v;if(!chunk){need(req.headers['content-type']?.split(';')[0]==='application/json','JSON content type required',415);try{v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}catch{throw new Refusal('invalid JSON');}}
   if(method==='POST'&&path==='/api/authorization-challenges')return send(res,pilot.challenge(v));
   if(method==='POST'&&path==='/api/attempts')return send(res,await pilot.attempt(v));
   if(method==='POST'&&path==='/api/registrations/challenge')return send(res,await pilot.registrationChallenge(v));
   if(method==='POST'&&path==='/api/registrations')return send(res,await pilot.registration(v));
   if(method==='POST'&&m?.[2]==='claim'&&!m[3])return send(res,pilot.refreshClaim(m[1],cap,v));
   if(method==='POST'&&m?.[2]==='execution'&&!m[3])return send(res,await pilot.execution(m[1],cap,v));
   if(method==='POST'&&m?.[2]==='evidence'&&!m[3])return send(res,pilot.beginEvidence(m[1],cap,v));
   if(chunk)return send(res,pilot.chunk(m[1],cap,m[3],decodeURIComponent(m[4]),req.headers['content-range'],raw));
   if(method==='POST'&&m?.[2]==='evidence'&&m[3]&&m[4]==='complete')return send(res,await pilot.complete(m[1],cap,m[3],v));
   throw new Refusal('route not found',404);
  }catch(e){send(res,{error:e instanceof Refusal?e.message:'operation refused; retained state requires inspection'},e instanceof Refusal?e.status:502);}
 });s.maxConnections=maxConnections;s.requestTimeout=60000;s.headersTimeout=15000;return s;
}
export function closedRange(header,bytes){
 if(header===undefined)return null;
 const m=typeof header==='string'&&/^bytes=(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$/.exec(header);
 need(m,'one closed byte range required',416);
 const start=Number(m[1]),end=Number(m[2]);
 need(Number.isSafeInteger(start)&&Number.isSafeInteger(end)&&start<=end&&end<bytes&&end-start+1<=4194304,'byte range outside bounds',416);
 return {start,end,length:end-start+1};
}
function file(req,res,f){
 let range;try{range=closedRange(req.headers.range,f.bytes);}catch(e){res.setHeader('Content-Range','bytes */'+f.bytes);throw e;}
 const headers={'Content-Type':'application/octet-stream','Content-Length':range?.length??f.bytes,'ETag':'"'+f.sha256+'"','Accept-Ranges':'bytes'};
 if(range)headers['Content-Range']=`bytes ${range.start}-${range.end}/${f.bytes}`;
 res.writeHead(range?206:200,headers);
 const stream=createReadStream(f.path,range?{start:range.start,end:range.end}:{});
 stream.on('error',()=>res.destroy());res.on('close',()=>stream.destroy());stream.pipe(res);
}
function send(res,v,status=200){res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(v)+'\n');}
async function body(req,max){const parts=[];let n=0;for await(const c of req){n+=c.length;need(n<=max,'body too large',413);parts.push(c);}return Buffer.concat(parts);}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const p=process.env.ARCADE_CONFIG;need(p&&statSync(p).isFile()&&(statSync(p).mode&0o077)===0,'protected ARCADE_CONFIG required');const c=JSON.parse(readFileSync(p));const pilot=new Pilot({...c,adapters:{}});pilot.basePath=c.basePath??'';pilot.adapters=remoteAdapters(pilot,walletVerifier(c.cast));need(/^[a-f0-9]{64}$/.test(c.worker_token_sha256),'worker token hash required');const s=server(pilot,{basePath:c.basePath??'',workerTokenHash:c.worker_token_sha256});s.listen(c.port??8080,'0.0.0.0',()=>console.log('Arcade pilot listening'));for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>s.close(()=>{pilot.close();process.exit(0);}));
}
