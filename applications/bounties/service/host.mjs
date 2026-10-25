import {mkdirSync,lstatSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {Pilot,need} from './core.mjs';
import {remoteAdapters,walletVerifier} from './adapters.mjs';
import {server} from './server.mjs';

// The operator supplies one immutable task and private state root per instance.
export function createHandler(config){
 need(config&&config.task&&typeof config.root==='string'&&config.root.startsWith('/'),'operator task and absolute state root required');
 mkdirSync(config.root,{recursive:true,mode:0o700});const st=lstatSync(config.root);
 need(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&(st.mode&0o077)===0,'private state root required');
 const pilot=new Pilot({root:config.root,dbPath:config.root+'/state.sqlite',task:config.task,origin:config.origin,adapters:{}});
 pilot.basePath=config.basePath;pilot.adapters=remoteAdapters(pilot,walletVerifier(config.cast));
 const service=server(pilot,{basePath:config.basePath,workerTokenHash:config.worker_token_sha256,webRoot:config.webRoot});
 const listener=service.listeners('request')[0];
 const handler=(req,res)=>{
  if(!req&&!res)return;
  const base=config.basePath??'',url=req.url;
  if(typeof url!=='string'||!url.startsWith('/')||url.startsWith('//')||/[\\\r\n]/.test(url)){res.writeHead(400);res.end('invalid request target');return;}
  const pathname=url.split('?')[0];
  // The existing pod host may remove its project prefix before delegation.
  if(base&&pathname!==base&&!pathname.startsWith(base+'/'))req.url=base+url;
  const local=req.url.slice(base.length);
  if(config.documentsRoot&&['GET','HEAD'].includes(req.method)&&['/terms.json','/policy.json'].includes(local)){
   const bytes=readFileSync(join(config.documentsRoot,local.slice(1)));res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Length':bytes.length,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(req.method==='HEAD'?undefined:bytes);return;
  }
  return listener(req,res);
 };
 handler.close=()=>pilot.close();return handler;
}
