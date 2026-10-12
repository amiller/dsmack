import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const script = fileURLToPath(new URL('./coupon_mac_admission_probe.mjs', import.meta.url));
const fixture = `import fs from 'node:fs';
export async function couponAttestedClient(peer, options, settings) {
 const event=name=>fs.appendFileSync(process.env.PROBE_TEST_EVENTS,name+'\\n');
 event('admit');
 if(settings.timeoutMs!==30000 || !options.stagingApproval.bytes.length || options.stagingApproval.approvalRoot!=='a'.repeat(64)) throw Error('PRIVATE-CANARY');
 const client={peerId:peer.split('/').at(-1),issuerProfile:'mac-appattest-coupon-v1',
 identity:{evidenceStatus:process.env.PROBE_TEST_BAD?'synthetic':'verified-apple-appattest-issuer-identity',
 appleAppId:'DC9JH5DRMY.dev.dsmack.provider',cdhash:'1'.repeat(64),composeSha256:'2'.repeat(64),
 runtimeAppAttested:true,runtimeApp:'fixture',policySha256:'3'.repeat(64),issuancePolicySha256:'4'.repeat(64),custody:'operator-kms-readable'},
 stagingAdmission:{issuerProfile:'mac-appattest-coupon-v1',approval_sha256:'5'.repeat(64)},
 close:async()=>event('close')};
 for(const name of ['offer','claim','wait','status','redeem','infer']) client[name]=()=>{event(name);throw Error('PRIVATE-CANARY');};
 return client;
}`;
function setup(fn) {
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'dsmack-public-probe-test-'));
 try {
  const root=path.join(directory,'source');fs.mkdirSync(path.join(root,'lib'),{recursive:true});
  fs.writeFileSync(path.join(root,'lib/coupon-attested.mjs'),fixture);
  const git=(...args)=>execFileSync('git',['-C',root,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','-b','main');git('add','lib/coupon-attested.mjs');
  git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture');
  const revision=git('rev-parse','HEAD');
  const pin=path.join(directory,'pin.json'),approval=path.join(directory,'approval.json'),events=path.join(directory,'events');
  fs.writeFileSync(pin,JSON.stringify({identityPolicy:{profile:'mac-appattest-coupon-v1'},
   expectedIdentityPolicySha256:'3'.repeat(64),expectedIssuancePolicySha256:'4'.repeat(64),expectedIssuerPublicKeySha256:'6'.repeat(64)}));
  fs.writeFileSync(approval,'public signed approval fixture');
  const args=['--source-revision',revision,root,pin,approval,'a'.repeat(64),'/dns4/issuer.example/tcp/443/wss/p2p/'+'b'.repeat(32)];
  const run=(input=args,env={})=>spawnSync(process.execPath,[script,...input],{encoding:'utf8',env:{...process.env,PROBE_TEST_EVENTS:events,...env}});
  fn({directory,root,pin,approval,args,events,run});
 } finally { fs.rmSync(directory,{recursive:true,force:true}); }
}
function failed(result) {
 assert.equal(result.status,1);assert.equal(result.stdout,'');
 assert.equal(result.stderr,'Mac public admission probe refused; no coupon or provider request was made.\n');
 assert.ok(!result.stderr.includes('PRIVATE-CANARY'));
}
test('only admission and close are invoked; output matches normalizer effect-free contract',()=>setup(({run,events})=>{
 const result=run();assert.equal(result.status,0,result.stderr);
 assert.equal(fs.readFileSync(events,'utf8'),'admit\nclose\n');
 const report=JSON.parse(result.stdout);
 assert.equal(report.profile,'mac-appattest-coupon-v1');assert.equal(report.runtimeApp,'fixture');
 for(const key of ['privateIssuanceQualified','rollbackQualified','couponRead','bearerSent','providerAdmitted','providerEffects']) assert.equal(report[key],false);
 assert.equal(report.approvalSha256,'5'.repeat(64));assert.ok(Number.isInteger(report.observed_at_unix));
}));
test('bad argument shape, revision, root or public route refuses before importing client',()=>setup(({run,args,events})=>{
 const variants=[args.slice(1),args.map((v,i)=>i===1?'0'.repeat(40):v),args.map((v,i)=>i===2?'relative':v),args.map((v,i)=>i===5?'secret':v),args.map((v,i)=>i===6?'https://user:secret@example.test':v)];
 for(const input of variants) failed(run(input));assert.equal(fs.existsSync(events),false);
}));
test('dirty tracked or unexpected untracked source refuses before importing',()=>setup(({run,root,events})=>{
 fs.appendFileSync(path.join(root,'lib/coupon-attested.mjs'),'\n// edited');failed(run());
 fs.writeFileSync(path.join(root,'lib/coupon-attested.mjs'),fixture);
 fs.writeFileSync(path.join(root,'lib/unreviewed.mjs'),'PRIVATE-CANARY');failed(run());
 assert.equal(fs.existsSync(events),false);
}));
test('bad, oversized, and symlink policy inputs refuse without echo',()=>setup(({run,pin,directory,events})=>{
 const original=fs.readFileSync(pin);
 fs.writeFileSync(pin,'{"secret":"PRIVATE-CANARY"}');failed(run());
 fs.writeFileSync(pin,Buffer.alloc(65537));failed(run());
 fs.unlinkSync(pin);const target=path.join(directory,'target');fs.writeFileSync(target,original);fs.symlinkSync(target,pin);failed(run());
 assert.equal(fs.existsSync(events),false);
}));
test('failed qualification closes client and emits no report',()=>setup(({run,events})=>{
 failed(run(undefined,{PROBE_TEST_BAD:'1'}));assert.equal(fs.readFileSync(events,'utf8'),'admit\nclose\n');
}));
