import {mkdirSync,lstatSync} from 'node:fs';
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
 const handler=(req,res)=>{if(!req&&!res)return;return listener(req,res);};
 handler.close=()=>pilot.close();return handler;
}
