import { createServer } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve, join } from 'node:path';
import { Store, need, Refusal, secretEqual } from './core.mjs';
import {taskPresentation} from './task-presentation.mjs';
import { verifyWebhook, normalizeWebhook } from './github.mjs';

const web=fileURLToPath(new URL('./web/',import.meta.url));
async function body(req){let n=0,parts=[];for await(const part of req){n+=part.length;need(n<=65536,'request too large',413);parts.push(part);}return Buffer.concat(parts);}
export function createApplication({store,operatorToken,webhookSecret,allowedRepositories=['amiller/bounty-arcade'],verdictAdmission,chainObservation,taskAnnotations=[]}){
  need(typeof operatorToken==='string'&&operatorToken.length>=32,'operator token must have at least 32 characters');
  const annotation=taskPresentation(store,taskAnnotations);
  return createServer(async(req,res)=>{
    const send=(status,v)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(v));};
    try{
      const u=new URL(req.url,'http://localhost');const path=u.pathname;need(!u.search,'query parameters unsupported');
      const token=()=>{const m=/^Bearer ([A-Za-z0-9_\-+/=]+)$/.exec(req.headers.authorization??'');need(m,'authorization required',401);return m[1];};
      const operator=()=>need(secretEqual(token(),operatorToken),'operator authorization required',401);
      if(req.method==='POST'&&path==='/github/webhook'){
        need(webhookSecret,'GitHub webhook not configured',503);const raw=await body(req);need(verifyWebhook(raw,req.headers['x-hub-signature-256'],webhookSecret),'invalid webhook signature',403);
        let value;try{value=JSON.parse(raw);}catch{throw new Refusal('invalid JSON');}
        const event=normalizeWebhook(req.headers['x-github-event'],value,{allowedRepositories});const fresh=store.delivery(req.headers['x-github-delivery'],raw,event);return send(202,{received:true,duplicate:!fresh,event});
      }
      if(req.method==='GET'&&path==='/api/tasks')return send(200,{tasks:store.list(),annotations:Object.fromEntries(store.list().map(t=>[t.id,annotation(t.id)]).filter(([,v])=>v))});
      let m=/^\/api\/tasks\/([a-z0-9-]{1,80})$/.exec(path);
      if(req.method==='GET'&&m)return send(200,{...store.detail(m[1]),annotation:annotation(m[1])});
      m=/^\/api\/tasks\/([a-z0-9-]{1,80})\/chain$/.exec(path);
      if(req.method==='GET'&&m){store.task(m[1]);return send(200,chainObservation?await chainObservation(m[1]):{status:'not_configured'});}
      if(req.method==='POST'&&path.startsWith('/api/')){
        need(req.headers['content-type']?.split(';')[0]==='application/json','application/json required',415);
        const raw=await body(req);let v;try{v=JSON.parse(raw);}catch{throw new Refusal('invalid JSON');}
        if(path==='/api/tasks'){operator();return send(201,{task:store.createTask(v)});}
        m=/^\/api\/tasks\/([a-z0-9-]{1,80})\/claim$/.exec(path);
        if(m){operator();return send(201,store.claim(m[1],v));}
        m=/^\/api\/attempts\/([a-f0-9]{32})\/(progress|submit|verdict)$/.exec(path);
        if(m){const[,id,action]=m;if(action==='verdict'){operator();return send(200,{attempt:verdictAdmission?await verdictAdmission(id,v):store.verdict(id,v)});}store.authorize(id,token());if(action==='progress')return send(201,{event:store.progress(id,v)});return send(200,{attempt:store.submit(id,v)});}
      }
      const files={'/':['index.html','text/html; charset=utf-8'],'/app.js':['app.js','text/javascript; charset=utf-8'],'/style.css':['style.css','text/css; charset=utf-8']};
      if(req.method==='GET'&&files[path]){const[name,type]=files[path];const bytes=readFileSync(join(web,name));res.writeHead(200,{'Content-Type':type,'Content-Length':bytes.length,'Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});return res.end(bytes);}
      send(404,{error:'not found'});
    }catch(e){if(e instanceof Refusal)return send(e.status,{error:e.message});send(500,{error:'internal error'});}
  });
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const state=process.env.BOUNTY_STATE;need(state,'BOUNTY_STATE required');const operatorPath=process.env.BOUNTY_OPERATOR_TOKEN_FILE;need(operatorPath,'BOUNTY_OPERATOR_TOKEN_FILE required');need((statSync(operatorPath).mode&0o077)===0,'operator token file must be private');
  const verifierKeys=process.env.BOUNTY_VERIFIER_KEYS_FILE?JSON.parse(readFileSync(process.env.BOUNTY_VERIFIER_KEYS_FILE,'utf8')):{};
  const allowedRepositories=(process.env.BOUNTY_REPOSITORIES??'amiller/bounty-arcade').split(',');const store=new Store(state,{verifierKeys,allowedRepositories});const server=createApplication({store,operatorToken:readFileSync(operatorPath,'utf8').trim(),webhookSecret:process.env.GITHUB_WEBHOOK_SECRET,allowedRepositories});
  const port=Number(process.env.PORT??8787);need(Number.isSafeInteger(port)&&port>0&&port<65536,'invalid port');server.listen(port,'127.0.0.1',()=>console.log('Bounty demo listening on http://127.0.0.1:'+port));
  const stop=()=>server.close(()=>{store.close();process.exit(0);});process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
