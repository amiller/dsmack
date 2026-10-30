import {createServer} from 'node:net';
import {HeaderCollector} from './receiver.mjs';
const enc=new TextEncoder();
// A receive-only SMTP endpoint: no AUTH, delivery queue or outbound relay.
export async function startSmtpReceiver({onHeaders,address,hostname='127.0.0.1',port=2525,maxConnections=20}) {
  if (!/^[^\s<>@]+@[^\s<>@]+$/.test(address)) throw Error('Configure one inbound address');
  const clients=new Set();
  const server=createServer(socket=>{
    if(clients.size>=maxConnections){socket.end('421 Busy\r\n');return;}
    clients.add(socket);socket.setTimeout(45_000,()=>socket.destroy());
    let buffer=Buffer.alloc(0),mail=false,recipient=false,data=null,chain=Promise.resolve();
    const reply=text=>socket.write(text+'\r\n');
    reply('220 dsmack recovery receiver');
    async function line(bytes){
      if(data){
        if(bytes.length===1&&bytes[0]===46){
          const collector=data;data=null;mail=false;recipient=false;
          try{await onHeaders(collector.finish());reply('250 Accepted');}catch{reply('554 Invalid recovery message');}
        }else{
          // SMTP dot unstuffing restores the sender's original signed headers.
          if(bytes[0]===46)bytes=bytes.subarray(1);
          try{data.write(bytes);data.write(enc.encode('\r\n'));}catch{reply('552 Message too large');socket.destroy();}
        }
        return;
      }
      const text=bytes.toString('utf8');
      if(/^(EHLO|HELO)\s+\S+/i.test(text))reply('250 dsmack');
      else if(/^MAIL FROM:\s*<[^<>\r\n]*>$/i.test(text)){mail=true;recipient=false;reply('250 Sender accepted');}
      else if(/^RCPT TO:/i.test(text)){
        const rcpt=/^RCPT TO:\s*<([^<>\r\n]+)>$/i.exec(text);
        if(!mail)reply('503 Send MAIL first');
        else if(rcpt&&rcpt[1].toLowerCase()===address.toLowerCase()){recipient=true;reply('250 Recipient accepted');}
        else reply('550 Unknown recipient');
      }else if(/^DATA$/i.test(text)){
        if(!recipient)reply('503 Send RCPT first');else{data=new HeaderCollector();reply('354 End with a dot');}
      }else if(/^RSET$/i.test(text)){mail=false;recipient=false;reply('250 Reset');}
      else if(/^NOOP$/i.test(text))reply('250 OK');
      else if(/^QUIT$/i.test(text))socket.end('221 Bye\r\n');
      else reply('502 Command unsupported');
    }
    socket.on('data',chunk=>{
      socket.pause();
      chain=chain.then(async()=>{
        buffer=Buffer.concat([buffer,chunk]);
        let end;
        while((end=buffer.indexOf('\r\n'))>=0){
          if(end>64*1024){reply('500 Line too long');socket.destroy();return;}
          const bytes=buffer.subarray(0,end);buffer=buffer.subarray(end+2);await line(bytes);
        }
        if(buffer.length>64*1024){reply('500 Line too long');socket.destroy();return;}
        socket.resume();
      }).catch(()=>socket.destroy());
    });
    socket.on('error',()=>{});socket.on('close',()=>clients.delete(socket));
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,hostname,resolve);});
  return {address:server.address(),close:async()=>{for(const client of clients)client.destroy();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}};
}
