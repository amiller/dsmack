const parentOrigin = "https://private-agent.dstack.soc1024.com";
const artifactOrigin = "https://artifacts.private-agent.dstack.soc1024.com";
const policy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data: blob:; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src blob:; worker-src 'self'; base-uri 'none'; form-action 'none'";
export const security = {
  "content-security-policy": policy + "; frame-ancestors " + parentOrigin + "; sandbox allow-scripts allow-same-origin allow-forms",
  "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff",
  "x-dns-prefetch-control": "off", "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()", "cache-control": "no-store",
};
const head = `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><meta http-equiv="x-dns-prefetch-control" content="off"><meta name="referrer" content="no-referrer"><title>Artifact</title><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}iframe{display:block}p{font:14px system-ui;padding:20px;line-height:1.5}</style><body>`;
const unavailableText = "App preview unavailable: this browser could not enforce native network isolation. Use an updated Chromium browser (152 or newer).";
const versionGate = `Number(navigator.userAgent.match(/(?:Chrome|Chromium|Edg)\\/(\\d+)/)?.[1] || 0) >= 152`;
export const loader = head + `<p>Checking browser network isolation…</p><script>
(async()=>{
 if(!(${versionGate})||!navigator.serviceWorker)throw Error('unsupported browser');
 const registration=await navigator.serviceWorker.register('/sandbox-sw.js',{scope:'/',updateViaCache:'none'});
 await registration.update(); await navigator.serviceWorker.ready;
 location.replace('/native-loader.html');
})().catch(()=>{document.body.textContent=${JSON.stringify(unavailableText)};parent.postMessage({type:'sandbox-unavailable',error:${JSON.stringify(unavailableText)}},${JSON.stringify(parentOrigin)})});
</script>`;
const probe = `<!doctype html><meta http-equiv="Content-Security-Policy" content="worker-src 'none'; frame-src 'none'"><script>
(async()=>{let pc;try{
 pc=new RTCPeerConnection({iceServers:[]});
 const failed=new Promise(resolve=>{pc.oniceconnectionstatechange=()=>{if(pc.iceConnectionState==='failed')resolve(true)};setTimeout(()=>resolve(false),1200)});
 pc.createDataChannel('native-policy-check');await pc.setLocalDescription(await pc.createOffer());
 const blocked=pc.iceConnectionState==='failed'||await failed;
 parent.postMessage({type:'native-policy-probe',blocked:blocked&&pc.iceConnectionState==='failed'},'*');
}catch{parent.postMessage({type:'native-policy-probe',blocked:false},'*')}finally{pc?.close()}})();
</script>`;
export const protectedLoader = head + `<p>Checking browser network isolation…</p><script>
const host=${JSON.stringify(parentOrigin)};
let inner,sandboxId,blob,probeFrame,nativeNetworkReady=false;
function unavailable(){document.body.textContent=${JSON.stringify(unavailableText)};parent.postMessage({type:'sandbox-unavailable',error:${JSON.stringify(unavailableText)}},host)}
function receive(event){const data=event.data;if(!data||typeof data!=='object')return;
 if(probeFrame&&event.source===probeFrame.contentWindow&&event.origin==='null'&&data.type==='native-policy-probe'){
  probeFrame.remove();probeFrame=null;
  if(!data.blocked){unavailable();return}nativeNetworkReady=true;document.body.replaceChildren();parent.postMessage({type:'sandbox-ready'},host);return;
 }
 if(inner&&event.source===inner.contentWindow&&event.origin==='null'){
  if(data.sandboxId===sandboxId&&['console','execution-complete','execution-error','dsmack-request'].includes(data.type))parent.postMessage(data,host);return;
 }
 if(event.source!==parent||event.origin!==host||!nativeNetworkReady)return;
 if(inner){if((data.type==='runtime-response'||data.type==='dsmack-response')&&data.sandboxId===sandboxId)inner.contentWindow.postMessage(data,'*');return}
 if(data.type!=='sandbox-load'||typeof data.code!=='string'||typeof data.sandboxId!=='string')return;
 sandboxId=data.sandboxId;inner=document.createElement('iframe');inner.sandbox.add('allow-scripts','allow-forms');inner.title='Generated app';
 const guard='<!doctype html><meta http-equiv="x-dns-prefetch-control" content="off"><meta http-equiv="Content-Security-Policy" content="worker-src &apos;none&apos;; frame-src &apos;none&apos;"><script>addEventListener("message",function(e){if(e.source!==parent||e.origin!=='+JSON.stringify(${JSON.stringify(artifactOrigin)})+'||!e.data||e.data.sandboxId!=='+JSON.stringify(sandboxId)+'){e.stopImmediatePropagation()}},true);<'+'/script>';
 blob=URL.createObjectURL(new Blob([guard,data.code],{type:'text/html'}));inner.src=blob;document.body.append(inner);
}
addEventListener('message',receive);
if(!(${versionGate})||!navigator.serviceWorker.controller){unavailable()}else{
 probeFrame=document.createElement('iframe');probeFrame.sandbox.add('allow-scripts');probeFrame.hidden=true;
 const probeUrl=URL.createObjectURL(new Blob([${JSON.stringify(probe).replaceAll("<", "\\u003c")}],{type:'text/html'}));
 probeFrame.src=probeUrl;document.body.append(probeFrame);setTimeout(()=>{URL.revokeObjectURL(probeUrl);if(!nativeNetworkReady&&probeFrame)unavailable()},2000);
}
</script>`;
export const serviceWorker = `self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{
 if(event.request.mode==='navigate'&&new URL(event.request.url).pathname==='/native-loader.html')event.respondWith(new Response(${JSON.stringify(protectedLoader)},{headers:{...${JSON.stringify(security)},'Connection-Allowlist':'()'}}));
});`;
export default function handler(req: Request) {
  const path = new URL(req.url).pathname;
  if (path !== "/loader.html" && path !== "/sandbox-sw.js") return new Response("Not found", { status: 404, headers: security });
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405, headers: { ...security, allow: "GET, HEAD" } });
  return new Response(req.method === "HEAD" ? null : path === "/sandbox-sw.js" ? serviceWorker : loader,
    { headers: path === "/sandbox-sw.js" ? { ...security, "content-type": "text/javascript; charset=utf-8" } : security });
}
if (import.meta.main) Deno.serve({ hostname: "127.0.0.1", port: Number(Deno.args[0] || "8789") }, handler);
