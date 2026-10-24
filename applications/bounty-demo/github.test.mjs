import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHmac, verify } from 'node:crypto';
import { verifyWebhook, normalizeWebhook, createAppJwt, GitHubAppClient } from './github.mjs';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const now = 1800000000000;
const repo = 'amiller/bounty-arcade';
const sha = 'a'.repeat(40);
test('raw body HMAC rejects forgery, normalization, missing secret and oversized input', () => {
 const raw = Buffer.from('{"unicode":"雪"}'); const secret = 'local-test-only';
 const sig = 'sha256=' + createHmac('sha256', secret).update(raw).digest('hex');
 assert.equal(verifyWebhook(raw, sig, secret), true);
 for (const [body, signature, key] of [[Buffer.from('{}'),sig,secret],[raw,'sha256='+'0'.repeat(64),secret],[raw,sig,''],[raw,'sha1=abc',secret],[raw.toString(),sig,secret],[Buffer.alloc(1048577),sig,secret]]) assert.equal(verifyWebhook(body,signature,key), false);
});
test('JWT has bounded clock claims and actual RSA signature', () => {
 const jwt = createAppJwt({ appId: 'Iv1.local', privateKey: pem, now }); const [h,p,s] = jwt.split('.');
 assert.deepEqual(JSON.parse(Buffer.from(h,'base64url')), { alg:'RS256',typ:'JWT' });
 assert.deepEqual(JSON.parse(Buffer.from(p,'base64url')), {iat:now/1000-60,exp:now/1000+540,iss:'Iv1.local'});
 assert.equal(verify('RSA-SHA256',Buffer.from(`${h}.${p}`),publicKey,Buffer.from(s,'base64url')),true);
 assert.throws(()=>createAppJwt({appId:'bad\n',privateKey:pem,now}));
 assert.throws(()=>createAppJwt({appId:1,privateKey:pem,now:NaN}));
});
test('webhook event projection excludes body/commands and rejects unlisted repos/actions', () => {
 const p = {action:'opened',repository:{full_name:repo},installation:{id:42},issue:{number:7,body:'run dangerous command'}};
 assert.deepEqual(normalizeWebhook('issues',p,{allowedRepositories:[repo]}),{type:'issue',action:'opened',repo,installation_id:42,issue_number:7});
 assert.equal(normalizeWebhook('issues',p,{allowedRepositories:[]}),null);
 assert.equal(normalizeWebhook('issue_comment',p,{allowedRepositories:[repo]}),null);
 assert.equal(normalizeWebhook('issues',{...p,installation:{id:'42'}},{allowedRepositories:[repo]}),null);
 assert.equal(normalizeWebhook('issues',{...p,action:'deleted'},{allowedRepositories:[repo]}),null);
});
function client(handler) { return new GitHubAppClient({appId:1,privateKey:pem,installations:[{repo,installationId:42}],now:()=>now,fetch:handler}); }
const tokenResponse = () => Response.json({token:'local-test-installation-token',expires_at:new Date(now+3600000).toISOString()});
test('installation scope is operator chosen and requested token is repository limited',async()=>{
 const calls=[]; const c=client(async(url,o)=>{calls.push({url,...o});return calls.length===1?tokenResponse():Response.json({number:7});});
 assert.deepEqual(await c.readIssue(repo,7),{number:7});
 assert.equal(calls[0].url,'https://api.github.com/app/installations/42/access_tokens');
 assert.deepEqual(JSON.parse(calls[0].body),{repositories:['bounty-arcade'],permissions:{issues:'read',contents:'read',checks:'write'}});
 assert.equal(calls[1].method,'GET');assert.equal(calls[1].headers['X-GitHub-Api-Version'],'2026-03-10');assert.equal(calls[1].redirect,'error');
 await assert.rejects(c.readIssue('evil/repo',7),/repository_not_allowed/);assert.equal(calls.length,2);
});
test('check create/update contract and no automatic retry after ambiguous failure',async()=>{
 const calls=[];const c=client(async(url,o)=>{calls.push({url,...o});return url.endsWith('access_tokens')?tokenResponse():Response.json({id:9});});
 await c.createCheckRun(repo,{name:'Dsmack evidence',head_sha:sha,status:'in_progress'});
 await c.updateCheckRun(repo,9,{name:'Dsmack evidence',status:'completed',conclusion:'success',output:{title:'Verified',summary:'Evidence checked; payment not made.'}});
 assert.equal(calls[1].method,'POST');assert.equal(calls[3].method,'PATCH');assert.ok(calls[3].url.endsWith('/check-runs/9'));
 await assert.rejects(c.createCheckRun(repo,{name:'x',head_sha:sha,status:'completed'}),/invalid_check_conclusion/);
 await assert.rejects(c.updateCheckRun(repo,9,{name:'x',status:'queued',command:'oops'}),/invalid_check_fields/);
 let n=0; const failed=client(async()=>{n++;return new Response('secret-provider-error',{status:429});});
 await assert.rejects(failed.readIssue(repo,1),e=>e.message==='github_http_429');assert.equal(n,1);
});
test('token expiry, transport errors and bounded response reject without leaking secrets',async()=>{
 await assert.rejects(client(async()=>Response.json({token:'secret',expires_at:new Date(now).toISOString()})).readIssue(repo,1),/invalid_installation_token/);
 await assert.rejects(client(async()=>{throw new Error('credential secret');}).readIssue(repo,1),e=>e.message==='github_transport_error');
 await assert.rejects(client(async()=>new Response('x'.repeat(1048577))).readIssue(repo,1),/github_invalid_response/);
});

test('repository path traversal configuration refused', () => {
 for (const bad of ['../repo','owner/..','owner/.','owner/repo?token=x','owner/repo/extra']) assert.throws(() => new GitHubAppClient({appId:1,privateKey:pem,installations:[{repo:bad,installationId:42}]}),/invalid_installation_scope/);
});
