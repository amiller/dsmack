import {test} from 'node:test';
import assert from 'node:assert/strict';
import {connect} from 'node:net';
import {HeaderCollector,HeaderReceiver} from './receiver.mjs';
import {startSmtpReceiver} from './smtp.mjs';
import {parseHeaders} from '../dkim-verifier.mjs';
const nonce='abcdefghijklmnopqrstuvwxyz';
const headers=`From: Person <person@example.test>\r\nSubject: dsmack-recover ${nonce}\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nDKIM-Signature: v=1; a=rsa-sha256;\r\n d=example.test; s=local; b=abc\r\n`;
const enc=new TextEncoder();
const raw=headers+'\r\nsecret message body\r\n';
const post=(receiver,body)=>receiver.handle(new Request('http://receiver/email-recovery/inbound',{method:'POST',headers:{'content-type':'message/rfc822'},body}));
const poll=(receiver)=>receiver.handle(new Request('http://receiver/email-recovery/headers/'+nonce));
const gmailHeaders=[
 'Return-path: <sender@gmail.com>',
 'Envelope-to: recover@soc1024.com',
 'Delivery-date: Fri, 30 Oct 2026 12:00:00 +0000',
 'Received: from mail-lf1-f42.google.com ([209.85.167.42])',
 '\tby mail.example.test with esmtps (TLS1.3) tls TLS_AES_256_GCM_SHA384',
 '\t(Exim 4.98) for recover@soc1024.com;',
 '\tFri, 30 Oct 2026 12:00:00 +0000',
 'Received: by mail-lf1-f42.google.com with SMTP id fixture.1',
 '        for <recover@soc1024.com>; Fri, 30 Oct 2026 05:00:00 -0700 (PDT)',
 'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;',
 '        d=gmail.com; s=20230601; t=1793361600; x=1793966400; darn=soc1024.com;',
 '        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject',
 '         :date:message-id:reply-to;',
 '        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;',
 '        b=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
 '         YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
 'X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;',
 '        d=1e100.net; s=20230601; b=YWJj',
 'MIME-Version: 1.0',
 'From: Sender <sender@gmail.com>',
 'Date: Fri, 30 Oct 2026 08:00:00 -0400',
 'Message-ID: <CAfixture-recovery-20261030@mail.gmail.com>',
 `Subject: dsmack-recover ${nonce}`,
 'To: recover@soc1024.com',
 'Content-Type: multipart/alternative; boundary="000000000000fixture"',
].join('\r\n')+'\r\n';
test('raw ingress preserves signed header bytes and discards body across chunk boundaries',async()=>{
 const receiver=new HeaderReceiver();
 try{
  const wire=enc.encode(raw);
  async function* parts(){for(let i=0;i<wire.length;i+=7)yield wire.subarray(i,i+7);}
  assert.equal(await receiver.receive(parts()),nonce);
  const response=await poll(receiver);assert.equal(response.status,200);
  assert.equal((await response.json()).headers,headers);
  assert.ok(!JSON.stringify([...receiver.messages.values()]).includes('secret message body'));
 }finally{receiver.close();}
});
test('Exim Gmail delivery drops the mbox envelope and restores LF headers before gate parsing',async()=>{
 const envelope='From sender@gmail.com Fri Oct 30 12:00:00 2026\n';
 const message=envelope+gmailHeaders.replace(/\r\n/g,'\n')+'\nsecret Gmail body\n';
 for(const chunkSize of [1,7,message.length]){
  const receiver=new HeaderReceiver();
  try{
   const wire=enc.encode(message);
   async function* parts(){for(let i=0;i<wire.length;i+=chunkSize)yield wire.subarray(i,i+chunkSize);}
   assert.equal(await receiver.receive(parts()),nonce);
   const received=await(await poll(receiver)).json();
   assert.equal(received.headers,gmailHeaders);
   const parsed=parseHeaders(received.headers);
   assert.equal(parsed.find(header=>header.name==='dkim-signature').raw,
    parseHeaders(gmailHeaders).find(header=>header.name==='dkim-signature').raw);
   assert.ok(!JSON.stringify(received).includes('secret Gmail body'));
  }finally{receiver.close();}
 }
});
test('HTTPS ingress accepts LF Gmail headers without an envelope and CRLF headers with one',async()=>{
 const receiver=new HeaderReceiver();
 try{
  for(const message of [gmailHeaders.replace(/\r\n/g,'\n')+'\nbody',
   'From sender@gmail.com Fri Oct 30 12:00:00 2026\r\n'+gmailHeaders+'\r\nbody']){
   assert.equal((await post(receiver,message)).status,202);
   assert.equal((await(await poll(receiver)).json()).headers,gmailHeaders);
  }
 }finally{receiver.close();}
});
test('header polling expires after fifteen minutes and does not consume the proof',async()=>{
 let now=1000;const receiver=new HeaderReceiver({now:()=>now});
 try{
  assert.equal((await poll(receiver)).status,202);
  assert.equal((await post(receiver,raw)).status,202);
  assert.equal((await poll(receiver)).status,200);assert.equal((await poll(receiver)).status,200);
  now+=15*60*1000;assert.equal((await poll(receiver)).status,202);assert.equal(receiver.messages.size,0);
 }finally{receiver.close();}
});
test('untrusted ingress rejects oversized headers, duplicate Subjects and missing nonce',async()=>{
 const receiver=new HeaderReceiver();
 try{
  for(const body of ['X: '+ 'a'.repeat(65536)+'\r\n\r\n',headers+'Subject: other\r\n\r\n','Subject: hello\r\n\r\n'])assert.equal((await post(receiver,body)).status,400);
  const collector=new HeaderCollector();collector.write(enc.encode(headers+'\r\n'));
  assert.throws(()=>collector.write(new Uint8Array(10*1024*1024)),/10 MiB/);
  assert.equal(receiver.messages.size,0);
 }finally{receiver.close();}
});
test('SMTP sink accepts only its inbound address, un-stuffs dots and serves raw headers',async()=>{
 const receiver=new HeaderReceiver();
 const smtp=await startSmtpReceiver({address:'recover@example.test',port:0,onHeaders:headers=>receiver.acceptHeaders(headers)});
 const socket=connect(smtp.address.port,'127.0.0.1');let buffer='';const waiters=[];
 socket.on('data',chunk=>{buffer+=chunk.toString();while(waiters.length&&buffer.includes('\r\n')){const end=buffer.indexOf('\r\n'),line=buffer.slice(0,end);buffer=buffer.slice(end+2);waiters.shift()(line);}});
 const response=()=>new Promise(resolve=>{if(buffer.includes('\r\n')){const end=buffer.indexOf('\r\n'),line=buffer.slice(0,end);buffer=buffer.slice(end+2);resolve(line);}else waiters.push(resolve);});
 const command=async(text,code)=>{socket.write(text+'\r\n');assert.equal((await response()).slice(0,3),code);};
 try{
  assert.equal((await response()).slice(0,3),'220');
  await command('EHLO local','250');await command('MAIL FROM:<person@example.test>','250');
  await command('RCPT TO:<other@example.test>','550');await command('RCPT TO:<recover@example.test>','250');await command('DATA','354');
  socket.write((headers+'\r\n.body should disappear\r\n').replace(/^\./gm,'..')+'.\r\n');assert.equal((await response()).slice(0,3),'250');
  const received=await(await poll(receiver)).json();assert.equal(received.headers,headers);
  await command('QUIT','221');
 }finally{socket.destroy();await smtp.close();receiver.close();}
});
