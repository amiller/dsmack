const parentOrigin = "https://private-agent.dstack.soc1024.com";
const policy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data: blob:; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src blob:; worker-src 'none'; base-uri 'none'; form-action 'none'";
export const security = {
  "content-security-policy": policy + "; frame-ancestors " + parentOrigin + "; sandbox allow-scripts",
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "x-dns-prefetch-control": "off",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "cache-control": "no-store",
};
export const loader = `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><meta http-equiv="x-dns-prefetch-control" content="off"><meta name="referrer" content="no-referrer"><title>Artifact</title><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}iframe{display:block}</style><script>
const host = ${JSON.stringify(parentOrigin)};
let inner, sandboxId, blob;
function receive(event) {
  const data = event.data;
  if (!data || typeof data !== 'object') return;
  if (inner && event.source === inner.contentWindow && event.origin === 'null') {
    if (data.sandboxId === sandboxId && ['console','execution-complete','execution-error','dsmack-request'].includes(data.type)) parent.postMessage(data, host);
    return;
  }
  if (event.source !== parent || event.origin !== host) return;
  if (inner) {
    if ((data.type === 'runtime-response' || data.type === 'dsmack-response') && data.sandboxId === sandboxId) inner.contentWindow.postMessage(data, '*');
    return;
  }
  if (data.type !== 'sandbox-load' || typeof data.code !== 'string' || typeof data.sandboxId !== 'string') return;
  sandboxId = data.sandboxId;
  inner = document.createElement('iframe');
  inner.sandbox.add('allow-scripts'); inner.title = 'Generated app';
  const guard = '<!doctype html><meta http-equiv="x-dns-prefetch-control" content="off"><meta http-equiv="Content-Security-Policy" content="frame-src &apos;none&apos;"><script>addEventListener("message",function(e){if(e.source!==parent||e.origin!=="null"||!e.data||e.data.sandboxId!==' + JSON.stringify(sandboxId) + '){e.stopImmediatePropagation()}},true);<' + '/script>';
  blob = URL.createObjectURL(new Blob([guard, data.code], {type:'text/html'}));
  inner.src = blob; document.body.append(inner);
}
addEventListener('message', receive);
parent.postMessage({type:'sandbox-ready'}, host);
</script><body></body>`;

export default function handler(req: Request) {
  if (new URL(req.url).pathname !== "/loader.html") return new Response("Not found", { status: 404, headers: security });
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405, headers: { ...security, allow: "GET, HEAD" } });
  return new Response(req.method === "HEAD" ? null : loader, { headers: security });
}
if (import.meta.main) Deno.serve({ hostname: "127.0.0.1", port: Number(Deno.args[0] || "8789") }, handler);
