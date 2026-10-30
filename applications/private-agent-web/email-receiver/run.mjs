import {createServer} from 'node:http';
import {HeaderReceiver} from './receiver.mjs';
import {startSmtpReceiver} from './smtp.mjs';
const receiver=new HeaderReceiver();
const hostname=process.env.RECEIVER_HOST||'127.0.0.1';
const address=process.env.RECOVERY_ADDRESS||'recover@private-agent.dstack.soc1024.com';
const inbound=process.env.INBOUND_URL;
const smtp=await startSmtpReceiver({address,hostname,port:Number(process.env.SMTP_PORT||2525),onHeaders:async headers=>{
  if(inbound){const result=await fetch(inbound,{method:'POST',headers:{'content-type':'message/rfc822'},body:headers+'\r\n',signal:AbortSignal.timeout(15_000)});if(!result.ok)throw Error('Inbound delivery failed');}
  else receiver.acceptHeaders(headers);
}});
const server=createServer(async(req,res)=>{
  try {
    const request=new Request('http://receiver'+req.url,{method:req.method,headers:req.headers,...(!['GET','HEAD'].includes(req.method)?{body:req,duplex:'half'}:{})});
    const response=await receiver.handle(request);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
  } catch {res.writeHead(400);res.end();}
});
await new Promise(resolve=>server.listen(Number(process.env.HTTP_PORT||8788),hostname,resolve));
console.log(JSON.stringify({smtp:smtp.address,http:server.address(),address,forwarding:Boolean(inbound)}));
async function close(){receiver.close();await smtp.close();server.close();}
process.once('SIGTERM',close);process.once('SIGINT',close);
