import {test} from 'node:test';
import assert from 'node:assert/strict';
import {connect} from 'node:net';
import {HeaderCollector,HeaderReceiver} from './receiver.mjs';
import {startSmtpReceiver} from './smtp.mjs';
const nonce='abcdefghijklmnopqrstuvwxyz';
const headers=`From: Person <person@example.test>\r\nSubject: dsmack-recover ${nonce}\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nDKIM-Signature: v=1; a=rsa-sha256;\r\n d=example.test; s=local; b=abc\r\n`;
const enc=new TextEncoder();
const raw=headers+'\r\nsecret message body\r\n';
const post=(receiver,body)=>receiver.handle(new Request('http://receiver/email-recovery/inbound',{method:'POST',headers:{'content-type':'message/rfc822'},body}));
const poll=(receiver)=>receiver.handle(new Request('http://receiver/email-recovery/headers/'+nonce));
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
