import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, timingSafeEqual, verify, createPublicKey } from 'node:crypto';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';

export class Refusal extends Error { constructor(message, status = 400) { super(message); this.status = status; } }
export function need(ok, message, status) { if (!ok) throw new Refusal(message, status); }
export function canonical(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') { need(Number.isSafeInteger(v), 'unsafe number'); return String(v); }
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  need(v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype, 'invalid object');
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
export const sha = v => createHash('sha256').update(v).digest('hex');
const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const commit = v => typeof v === 'string' && /^[a-f0-9]{40}$/.test(v);
const label = (v, max = 120) => typeof v === 'string' && v.length > 0 && v.length <= max && !/[\x00-\x1f\x7f]/.test(v);
export function exact(v, required, optional = []) { need(v && typeof v === 'object' && !Array.isArray(v), 'object required'); need(required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => [...required, ...optional].includes(k)), 'unexpected or missing fields'); }
export function secretEqual(a, b) { return typeof a === 'string' && typeof b === 'string' && timingSafeEqual(Buffer.from(sha(a), 'hex'), Buffer.from(sha(b), 'hex')); }
const phases = new Set(['launch','boot','pull','agent','review','verify','done']);
const kinds = new Set(['phase','heartbeat','tool','usage']);

export class Store {
  constructor(path, { verifierKeys = {}, allowedRepositories = ['amiller/bounty-arcade'], now = () => Math.floor(Date.now()/1000) } = {}) {
    if (path !== ':memory:') { mkdirSync(dirname(path), {recursive:true, mode:0o700}); }
    this.db = new DatabaseSync(path); if(path!==':memory:') chmodSync(path,0o600);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY, task_id TEXT UNIQUE REFERENCES tasks(id), token_hash TEXT NOT NULL, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events(attempt_id TEXT REFERENCES attempts(id), seq INTEGER, body TEXT NOT NULL, PRIMARY KEY(attempt_id,seq)); CREATE TABLE IF NOT EXISTS claim_requests(request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, request_hash TEXT NOT NULL, attempt_id TEXT NOT NULL REFERENCES attempts(id)); CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY, digest TEXT NOT NULL, body TEXT NOT NULL);');
    this.verifierKeys = Object.fromEntries(Object.entries(verifierKeys).map(([k,v])=>{ const key=createPublicKey(v); need(key.asymmetricKeyType==='ed25519','verifier must use Ed25519'); return [k,key]; }));
    this.allowed = allowedRepositories; this.now=now;
  }
  close(){this.db.close();}
  tx(fn){this.db.exec('BEGIN IMMEDIATE');try{const r=fn();this.db.exec('COMMIT');return r;}catch(e){this.db.exec('ROLLBACK');throw e;}}
  task(id){const r=this.db.prepare('SELECT body FROM tasks WHERE id=?').get(id);need(r,'task not found',404);return JSON.parse(r.body);}
  attempt(id){const r=this.db.prepare('SELECT body FROM attempts WHERE id=?').get(id);need(r,'attempt not found',404);return JSON.parse(r.body);}
  list(){return this.db.prepare('SELECT body FROM tasks ORDER BY id').all().map(x=>JSON.parse(x.body));}
  detail(id){const task=this.task(id);const row=this.db.prepare('SELECT body FROM attempts WHERE task_id=?').get(id);const attempt=row?JSON.parse(row.body):null;return {task,attempt,events:attempt?this.db.prepare('SELECT body FROM events WHERE attempt_id=? ORDER BY seq').all(attempt.id).map(x=>JSON.parse(x.body)):[]};}
  saveTask(t){this.db.prepare('UPDATE tasks SET body=? WHERE id=?').run(canonical(t),t.id);}
  saveAttempt(a){this.db.prepare('UPDATE attempts SET body=? WHERE id=?').run(canonical(a),a.id);const t=this.task(a.task_id);t.state=a.state;this.saveTask(t);}
  createTask(v){
    exact(v,['id','repo','issue_number','title','base_commit','checker_sha256','image_sha256','harness_sha256','reward']);
    need(typeof v.id==='string'&&/^[a-z0-9-]{1,80}$/.test(v.id),'invalid task id');
    need(this.allowed.includes(v.repo),'repository not admitted');need(Number.isSafeInteger(v.issue_number)&&v.issue_number>0,'invalid issue');need(label(v.title,240),'invalid title');need(commit(v.base_commit),'invalid base commit');
    for(const k of ['checker_sha256','image_sha256','harness_sha256'])need(hex(v[k]),'invalid '+k);
    exact(v.reward,['amount','asset','chain']);need(typeof v.reward.amount==='string'&&/^\d{1,12}(\.\d{1,18})?$/.test(v.reward.amount),'invalid amount');need(label(v.reward.asset,20)&&label(v.reward.chain,40),'invalid reward display');
    const terms=JSON.parse(canonical(v));const t={...terms,terms_sha256:sha(canonical(terms)),state:'open',funding_status:'unfunded',created_at:this.now()};
    return this.tx(()=>{need(!this.db.prepare('SELECT 1 FROM tasks WHERE id=?').get(t.id),'task already exists',409);this.db.prepare('INSERT INTO tasks VALUES(?,?)').run(t.id,canonical(t));return t;});
  }
  claim(id,v){exact(v,['worker','payee'],['request_id','capability']);need(label(v.worker,80),'invalid worker');need(typeof v.payee==='string'&&/^0x[0-9a-fA-F]{40}$/.test(v.payee),'invalid payee');
    const durable=Object.hasOwn(v,'request_id')||Object.hasOwn(v,'capability');
    if(durable){need(typeof v.request_id==='string'&&/^[a-f0-9]{64}$/.test(v.request_id),'invalid claim request id');need(typeof v.capability==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v.capability)&&Buffer.from(v.capability,'base64url').length===32&&Buffer.from(v.capability,'base64url').toString('base64url')===v.capability,'invalid claim capability');}
    const requestHash=durable?sha(canonical({task_id:id,worker:v.worker,payee:v.payee.toLowerCase(),capability_hash:sha(v.capability)})):null;
    return this.tx(()=>{if(durable){const old=this.db.prepare('SELECT request_hash,attempt_id FROM claim_requests WHERE request_id=?').get(v.request_id);if(old){need(secretEqual(old.request_hash,requestHash),'conflicting claim retry',409);const a=this.attempt(old.attempt_id);this.authorize(a.id,v.capability);return {attempt:a,token:v.capability};}}
      const t=this.task(id);need(t.state==='open','task already assigned',409);const token=durable?v.capability:randomBytes(32).toString('base64url');const a={id:randomBytes(16).toString('hex'),task_id:id,worker:v.worker,payee:v.payee.toLowerCase(),nonce:randomBytes(32).toString('hex'),state:'claimed',created_at:this.now()};this.db.prepare('INSERT INTO attempts VALUES(?,?,?,?)').run(a.id,id,sha(token),canonical(a));if(durable)this.db.prepare('INSERT INTO claim_requests VALUES(?,?,?,?)').run(v.request_id,id,requestHash,a.id);this.saveAttempt(a);return {attempt:a,token};});
  }
  authorize(id,token){const r=this.db.prepare('SELECT token_hash FROM attempts WHERE id=?').get(id);need(r&&typeof token==='string'&&secretEqual(r.token_hash,sha(token)),'attempt authorization required',401);}
  progress(id,v){exact(v,['phase','kind'],['counters']);need(phases.has(v.phase)&&kinds.has(v.kind),'invalid progress');const counters=v.counters??{};exact(counters,[],['turns','input_tokens','output_tokens','elapsed_ms']);need(Object.values(counters).every(x=>Number.isSafeInteger(x)&&x>=0&&x<=1e12),'invalid counters');
    return this.tx(()=>{const a=this.attempt(id);need(['claimed','running'].includes(a.state),'attempt not running',409);const seq=Number(this.db.prepare('SELECT count(*) n FROM events WHERE attempt_id=?').get(id).n)+1;need(seq<=10000,'progress limit reached',429);const e={seq,phase:v.phase,kind:v.kind,counters,received_at:this.now(),advisory:true};this.db.prepare('INSERT INTO events VALUES(?,?,?)').run(id,seq,canonical(e));a.state='running';this.saveAttempt(a);return e;});
  }
  submit(id,v){exact(v,['candidate_sha256','bundle_sha256'],['commit_sha']);need(hex(v.candidate_sha256)&&hex(v.bundle_sha256),'invalid submitted hashes');if(v.commit_sha!==undefined)need(commit(v.commit_sha),'invalid commit');
    return this.tx(()=>{const a=this.attempt(id);if(a.submission){need(canonical(a.submission)===canonical(v),'conflicting submission',409);return a;}need(['claimed','running'].includes(a.state),'attempt cannot submit',409);Object.assign(a,v,{submission:v,state:'submitted'});this.saveAttempt(a);return a;});
  }
  verdict(id,cert){
    exact(cert,['payload','signature','key_id']);const p=cert.payload;exact(p,['schema','task_id','terms_sha256','attempt_id','nonce','payee','candidate_sha256','bundle_sha256','checker_sha256','image_sha256','harness_sha256','report_sha256','accepted','checks','issued_at','expires_at']);
    need(p.schema==='dsmack-bounty-verdict/1','wrong verdict domain');const key=this.verifierKeys[cert.key_id];need(key,'verifier not configured',503);need(typeof cert.signature==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(cert.signature),'invalid signature encoding');need(verify(null,Buffer.from(canonical(p)),key,Buffer.from(cert.signature,'base64')),'invalid verifier signature',403);
    return this.tx(()=>{const a=this.attempt(id);if(a.verdict){need(canonical(a.verdict)===canonical(cert),'conflicting verdict',409);return a;}need(a.state==='submitted','submission required',409);const t=this.task(a.task_id);
      for(const [k,want] of Object.entries({task_id:t.id,terms_sha256:t.terms_sha256,attempt_id:a.id,nonce:a.nonce,payee:a.payee,candidate_sha256:a.candidate_sha256,bundle_sha256:a.bundle_sha256,checker_sha256:t.checker_sha256,image_sha256:t.image_sha256,harness_sha256:t.harness_sha256}))need(p[k]===want,'verdict binding mismatch: '+k,403);
      const admissionNow=this.now();
      need(hex(p.report_sha256),'invalid report digest');need(Number.isSafeInteger(p.issued_at)&&Number.isSafeInteger(p.expires_at)&&p.issued_at<=admissionNow+30&&p.issued_at>=a.created_at&&p.expires_at>admissionNow&&p.expires_at>p.issued_at&&p.expires_at-p.issued_at<=3600,'stale verdict',403);
      exact(p.checks,['apple','outputs','functional']);need(typeof p.accepted==='boolean'&&Object.values(p.checks).every(v=>typeof v==='boolean'),'invalid verdict checks');need(!p.accepted||Object.values(p.checks).every(Boolean),'incomplete accepted verdict',403);
      a.state=p.accepted?'verified':'failed';a.verdict=cert;a.verdict_received_at=admissionNow;a.reward_status='unpaid';this.saveAttempt(a);return a;
    });
  }
  delivery(id,raw,event){need(typeof id==='string'&&/^[a-zA-Z0-9-]{1,100}$/.test(id),'invalid delivery id');return this.tx(()=>{const digest=sha(raw);const old=this.db.prepare('SELECT digest FROM deliveries WHERE id=?').get(id);if(old){need(old.digest===digest,'conflicting delivery',409);return false;}this.db.prepare('INSERT INTO deliveries VALUES(?,?,?)').run(id,digest,canonical(event));return true;});}
}
