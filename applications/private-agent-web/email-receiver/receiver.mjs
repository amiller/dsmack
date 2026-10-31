// Inbound email is untrusted. Bodies are discarded while the input is streamed.
const NONCE = /^[a-z2-7]{26}$/;
const HEADER_LIMIT = 64 * 1024, MESSAGE_LIMIT = 10 * 1024 * 1024;
const TTL = 15 * 60 * 1000;
export class HeaderCollector {
  constructor() { this.header = new Uint8Array(0); this.size = 0; this.complete = false; }
  write(chunk) {
    this.size += chunk.length;
    if (this.size > MESSAGE_LIMIT) throw Error('Message exceeds 10 MiB');
    if (this.complete) return;
    // Keep at most a header plus the delimiter, even if one chunk is a whole message.
    const part = chunk.subarray(0, HEADER_LIMIT + 4 - this.header.length);
    const joined = new Uint8Array(this.header.length + part.length);
    joined.set(this.header); joined.set(part, this.header.length);
    for (let i = Math.max(0, this.header.length - 3); i + 1 < joined.length; i++) {
      if (joined[i] === 10 && (joined[i+1] === 10 || (joined[i+1] === 13 && joined[i+2] === 10))) {
        const end = i > 0 && joined[i-1] === 13 ? i - 1 : i;
        this.header = joined.slice(0, end); this.complete = true; return;
      }
    }
    this.header = joined;
    if (joined.length >= HEADER_LIMIT + 4) throw Error('Headers exceed 64 KiB');
  }
  finish() {
    if (!this.complete) throw Error('Message has no header delimiter');
    // Exim pipe delivery uses LF and may prepend an mbox envelope. The envelope
    // is not a signed header; restore RFC line endings without changing values.
    return new TextDecoder('utf-8', {fatal:true}).decode(this.header)
      .replace(/^From [^\r\n]*\r?\n/, '').replace(/\r?\n/g, '\r\n') + '\r\n';
  }
}
export class HeaderReceiver {
  constructor({now = Date.now, maxEntries = 512} = {}) { this.now=now; this.maxEntries=maxEntries; this.messages=new Map(); this.timers=new Map(); }
  prune() { for (const [nonce, value] of this.messages) if (value.expiresAt <= this.now()) { this.messages.delete(nonce); clearTimeout(this.timers.get(nonce)); this.timers.delete(nonce); } }
  close() { for (const timer of this.timers.values()) clearTimeout(timer); this.timers.clear(); this.messages.clear(); }
  acceptHeaders(headers) {
    if (new TextEncoder().encode(headers).length > HEADER_LIMIT || /\0/.test(headers)) throw Error('Invalid headers');
    const fields = headers.replace(/\r\n[ \t]+/g, ' ').split('\r\n');
    const subjects = fields.filter(line => /^subject:/i.test(line));
    if (subjects.length !== 1) throw Error('Expected one recovery Subject');
    const match = /^subject:[ \t]*dsmack-recover[ \t]+([a-z2-7]{26})[ \t]*$/i.exec(subjects[0]);
    if (!match) throw Error('Expected recovery nonce in Subject');
    const nonce=match[1].toLowerCase(); this.prune();
    if (!this.messages.has(nonce) && this.messages.size >= this.maxEntries) throw Error('Receiver is full');
    this.messages.set(nonce, {nonce, headers, expiresAt:this.now()+TTL});
    clearTimeout(this.timers.get(nonce));
    const timer=setTimeout(()=>{this.messages.delete(nonce);this.timers.delete(nonce);},TTL);
    timer.unref?.(); if(typeof timer==='number')globalThis.Deno?.unrefTimer?.(timer); this.timers.set(nonce,timer);
    return nonce;
  }
  async receive(chunks) {
    const collector=new HeaderCollector();
    for await (const chunk of chunks) collector.write(chunk);
    return this.acceptHeaders(collector.finish());
  }
  async handle(req) {
    const path=new URL(req.url).pathname;
    const json=(body,status=200)=>Response.json(body,{status,headers:{'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'}});
    if (path === '/email-recovery/inbound') {
      if (req.method !== 'POST') return json({error:'Use POST'},405);
      if (!/^message\/rfc822(?:;|$)/i.test(req.headers.get('content-type')||'')) return json({error:'Use message/rfc822'},415);
      if (Number(req.headers.get('content-length')||0)>MESSAGE_LIMIT) return json({error:'Message exceeds 10 MiB'},413);
      try { return json({nonce:await this.receive(req.body || [])},202); }
      catch { return json({error:'Invalid recovery message'},400); }
    }
    const match=/^\/email-recovery\/headers\/([a-z2-7]{26})$/i.exec(path);
    if (!match) return json({error:'Not found'},404);
    if (req.method !== 'GET') return json({error:'Use GET'},405);
    const nonce=match[1].toLowerCase();
    if (!NONCE.test(nonce)) return json({error:'Invalid nonce'},400);
    this.prune(); const value=this.messages.get(nonce);
    return value ? json(value) : json({pending:true},202);
  }
}
