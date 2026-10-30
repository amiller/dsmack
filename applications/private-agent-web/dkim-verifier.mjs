import {bytes,unb64,emailRecoveryNonce} from './email-gate-crypto.mjs';
const reject=(message)=>{throw Error(message);};
const compact=(s)=>s.replace(/[ \t\r\n]/g,'');
const domain=/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const selector=/^(?=.{1,253}$)[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*$/i;
export function parseHeaders(raw) {
  if(typeof raw!=='string'||raw.length>32768||/\r(?!\n)|(?<!\r)\n/.test(raw))reject('Invalid raw email headers');
  raw=raw.split('\r\n\r\n',1)[0];
  const result=[];
  for(const line of raw.split('\r\n')) {
    if(!line)continue;
    if(/^[ \t]/.test(line)){if(!result.length)reject('Invalid folded email header');result.at(-1).raw+='\r\n'+line;continue;}
    const colon=line.indexOf(':');
    if(colon<1||! /^[\x21-\x39\x3b-\x7e]+[ \t]*$/.test(line.slice(0,colon)))reject('Invalid email header');
    result.push({name:line.slice(0,colon).trim().toLowerCase(),raw:line});
  }
  return result;
}
export const headerValue=(header)=>header.raw.slice(header.raw.indexOf(':')+1).replace(/\r\n[ \t]+/g,' ').trim();
export function canonicalHeader(header,mode='relaxed') {
  if(mode==='simple')return header.raw+'\r\n';
  if(mode!=='relaxed')reject('Unsupported DKIM canonicalization');
  const colon=header.raw.indexOf(':');
  return header.raw.slice(0,colon).trim().toLowerCase()+':'+header.raw.slice(colon+1).replace(/\r\n[ \t]+/g,' ').replace(/[ \t]+/g,' ').trim()+'\r\n';
}
export function dkimTags(value) {
  const tags={};
  for(const piece of value.split(';')) {
    if(!piece.trim())continue;
    const m=piece.match(/^\s*([a-z][a-z0-9_]*)\s*=([\s\S]*)$/i);if(!m)reject('Invalid DKIM tag');
    const name=m[1].toLowerCase();if(Object.hasOwn(tags,name))reject('Duplicate DKIM tag');tags[name]=m[2].trim();
  }
  return tags;
}
export function signatureInput(headers,signature) {
  const tags=dkimTags(headerValue(signature)),canonical=(tags.c||'simple/simple').toLowerCase();
  if(!/^(simple|relaxed)(\/(simple|relaxed))?$/.test(canonical))reject('Unsupported DKIM canonicalization');
  const mode=canonical.split('/')[0];
  const used=new Set([signature]),parts=[];
  for(const name of compact(tags.h||'').toLowerCase().split(':')) {
    if(!/^[\x21-\x39\x3b-\x7e]+$/.test(name))reject('Invalid DKIM signed header list');
    const field=headers.findLast(h=>h.name===name&&!used.has(h));
    if(field){used.add(field);parts.push(canonicalHeader(field,mode));}
  }
  // RFC6376 section3.7: omit b= value, including its folding whitespace,
  // and omit the final CRLF only on this DKIM-Signature header.
  const empty={...signature,raw:signature.raw.replace(/([;:]\s*b[ \t]*=)[^;]*/i,'$1')};
  parts.push(canonicalHeader(empty,mode).slice(0,-2));
  return bytes(parts.join(''));
}
function derLength(length){if(length<128)return [length];const out=[];while(length){out.unshift(length&255);length>>>=8;}return [128|out.length,...out];}
export async function rsaKey(record) {
  const tags=dkimTags(record);
  if(tags.v&&tags.v!=='DKIM1'||tags.k&&tags.k.toLowerCase()!=='rsa'||!tags.p)reject('No usable RSA DKIM key');
  if(tags.h&&!compact(tags.h).toLowerCase().split(':').includes('sha256'))reject('DKIM key does not allow SHA256');
  if(tags.s&&!compact(tags.s).toLowerCase().split(':').some(s=>s==='*'||s==='email'))reject('DKIM key does not allow email');
  let key;const der=unb64(compact(tags.p)),algorithm={name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'};
  try{key=await crypto.subtle.importKey('spki',der,algorithm,false,['verify']);}
  catch{
    // RFC6376 p= permits the PKCS#1 RSAPublicKey encoding as well as SPKI.
    const bitString=[3,...derLength(der.length+1),0,...der],oid=[48,13,6,9,42,134,72,134,247,13,1,1,1,5,0];
    key=await crypto.subtle.importKey('spki',new Uint8Array([48,...derLength(oid.length+bitString.length),...oid,...bitString]),algorithm,false,['verify']);
  }
  return key;
}
export async function verifyHeaderSignature(headers,signature,record) {
  const tags=dkimTags(headerValue(signature));
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5',await rsaKey(record),unb64(compact(tags.b||'')),signatureInput(headers,signature));
}
function txtData(data) {
  if(typeof data!=='string')reject('Invalid DNS TXT response');
  if(!data.trim().startsWith('"'))return data.trim();
  const chunks=[...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
  if(!chunks.length||data.replace(/"((?:[^"\\]|\\.)*)"/g,'').trim())reject('Invalid DNS TXT response');
  return chunks.map(m=>m[1].replace(/\\([0-9]{3}|.)/gs,(_,c)=>/^\d{3}$/.test(c)?String.fromCharCode(Number(c)):c)).join('');
}
export const DOH_RESOLVERS=['https://cloudflare-dns.com/dns-query','https://dns.google/resolve'];
export async function fetchDkimKey(name,{fetch:fetcher=fetch,resolvers=DOH_RESOLVERS}={}) {
  const records=await Promise.all(resolvers.map(async(base)=>{
    const url=new URL(base);url.searchParams.set('name',name);url.searchParams.set('type','TXT');
    const response=await fetcher(url,{headers:{accept:'application/dns-json'},signal:AbortSignal.timeout(10000)});
    if(!response.ok)reject('DKIM DNS lookup failed');
    const raw=await response.text();if(raw.length>65536)reject('DKIM DNS response too large');
    const result=JSON.parse(raw);if(result.Status!==0||result.TC)reject('DKIM DNS lookup failed');
    const txt=(result.Answer||[]).filter(r=>r.type===16).map(r=>txtData(r.data)).filter(r=>/(?:^|;)\s*p\s*=/i.test(r));
    if(txt.length!==1)reject('Expected one DKIM key record');return txt[0];
  }));
  const normalized=records.map(record=>Object.entries(dkimTags(record)).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>k+'='+compact(v)).join(';'));
  if(records.length!==2||normalized[0]!==normalized[1])reject('DKIM DNS resolvers disagree');
  return records[0];
}
export async function verifyDkimRecovery({headers:raw,email,userId,ts,publicKey,nonce},{now=Date.now(),lookup=fetchDkimKey}={}) {
  if(typeof email!=='string'||email!==email.trim().toLowerCase()||email.length>254||! /^[^\s<>@,]+@[^\s<>@,]+\.[^\s<>@,]+$/.test(email))reject('Invalid recovery address');
  if(typeof userId!=='string'||!userId||userId.length>254)reject('Invalid recovery user');
  if(!Number.isSafeInteger(ts)||Math.abs(now-ts)>30*60_000)reject('Recovery request expired');
  try{await crypto.subtle.importKey('raw',unb64(publicKey),{name:'ECDH',namedCurve:'P-256'},false,[]);}catch{reject('Invalid browser public key');}
  const expected=await emailRecoveryNonce(publicKey,userId,ts);
  if(nonce!==undefined&&nonce!==expected)reject('Recovery nonce mismatch');
  const headers=parseHeaders(raw),one=(name)=>{const list=headers.filter(h=>h.name===name);if(list.length!==1)reject('Expected one '+name+' header');return headerValue(list[0]);};
  const from=one('from'),mailbox=from.match(/^(?:[^<>]*<)?([^\s<>@,]+@[^\s<>@,]+)>?$/);
  if(!mailbox||mailbox[1].toLowerCase()!==email)reject('Recovery sender does not match address');
  const fromDomain=email.split('@')[1];
  if(one('subject')!=='dsmack-recover '+expected)reject('Recovery subject does not match browser nonce');
  const date=Date.parse(one('date'));if(!Number.isFinite(date)||Math.abs(now-date)>30*60_000)reject('Recovery email expired');
  let reason='No aligned DKIM signature';
  for(const signature of headers.filter(h=>h.name==='dkim-signature')) {
    try {
      const t=dkimTags(headerValue(signature)),d=compact(t.d||'').toLowerCase(),s=compact(t.s||''),h=compact(t.h||'').toLowerCase().split(':');
      if(!domain.test(d)||!(fromDomain===d||fromDomain.endsWith('.'+d)))continue;
      if(t.v!=='1'||t.a?.toLowerCase()!=='rsa-sha256')reject('DKIM requires RSA-SHA256');
      if(Object.hasOwn(t,'l'))reject('DKIM body length is not allowed');
      if(!['from','subject','date'].every(n=>h.includes(n)))reject('DKIM must sign From, Subject and Date');
      if(!selector.test(s))reject('Invalid DKIM selector');
      if(t.q&&!compact(t.q).toLowerCase().split(':').includes('dns/txt'))reject('Unsupported DKIM query method');
      if(t.x&&(!/^\d+$/.test(t.x)||Number(t.x)*1000<now))reject('DKIM signature expired');
      const record=await lookup(s+'._domainkey.'+d),key=await rsaKey(record);
      if(key.algorithm.modulusLength<2048)reject('DKIM key must be at least 2048 bits');
      if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unb64(compact(t.b||'')),signatureInput(headers,signature)))reject('DKIM signature verification failed');
      return {email,userId,nonce:expected,domain:d,selector:s};
    }catch(e){reason=e.message;}
  }
  reject(reason);
}
