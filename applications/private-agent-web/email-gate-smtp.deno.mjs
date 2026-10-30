import {smtp} from './email-gate-runtime.mjs';
const enc=new TextEncoder(),dec=new TextDecoder();
Deno.test('SMTP adapter delivers recovery code to a local sink',async()=>{
 const listener=Deno.listen({hostname:'127.0.0.1',port:0});let message='';
 const server=(async()=>{
  const conn=await listener.accept();
  await conn.write(enc.encode('220 sink\r\n'));let buffer='',data=false;
  try{while(true){const bytes=new Uint8Array(4096),n=await conn.read(bytes);if(n===null)break;buffer+=dec.decode(bytes.subarray(0,n));let pos;while((pos=buffer.indexOf('\r\n'))>=0){const line=buffer.slice(0,pos);buffer=buffer.slice(pos+2);let reply='250 ok';if(data){if(line==='.')data=false;else{message+=line+'\n';continue;}}else if(line==='DATA'){data=true;reply='354 send';}else if(line==='QUIT')reply='221 bye';await conn.write(enc.encode(reply+'\r\n'));if(line==='QUIT')return;}}}finally{conn.close();}
 })();
 try{await smtp({SMTP_HOST:'127.0.0.1',SMTP_PORT:String(listener.addr.port),SMTP_TLS:'false',SMTP_FROM:'private-agent@example.invalid'},{to:'recover@example.invalid',code:'123456'});await server;if(!message.includes('Your code is 123456'))throw Error('Recovery code missing from SMTP message');}
 finally{listener.close();}
});
