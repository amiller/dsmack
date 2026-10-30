import https from "node:https";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loader, serviceWorker } from "../private-agent-artifacts/server.ts";

// Service worker script registration uses the browser's network stack, beyond
// Playwright frame routing. Serve it over real local TLS, with no proxy headers.
export async function artifactTestServer({ mainHtml = "", mainScript = "", mainRoot } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "dsmack-artifact-tls-"));
  const key = join(directory, "key.pem"), cert = join(directory, "cert.pem");
  await promisify(execFile)("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=artifacts.private-agent.dstack.soc1024.com", "-keyout", key, "-out", cert]);
  const server = https.createServer({ key: await readFile(key), cert: await readFile(cert) }, async (req, res) => {
    if (mainRoot && req.headers.host === "private-agent.dstack.soc1024.com") {
      const path = new URL(req.url, "https://test.invalid").pathname.replace(/^\/a\/?/, "") || "index.html";
      try { res.setHeader("content-type", {js:"text/javascript",css:"text/css",html:"text/html",json:"application/json"}[path.split('.').at(-1)] || "application/octet-stream");res.end(await readFile(join(mainRoot,path))); }
      catch { res.statusCode=404;res.end("Not found"); }return;
    }
    if (req.headers.host === "private-agent.dstack.soc1024.com" && req.url === "/") { res.setHeader("content-type", "text/html"); res.end(mainHtml); }
    else if (req.headers.host === "private-agent.dstack.soc1024.com" && req.url === "/test.js") { res.setHeader("content-type", "text/javascript"); res.end(mainScript); }
    else if (req.url === "/sandbox-sw.js") { res.setHeader("content-type", "text/javascript"); res.end(serviceWorker); }
    else if (req.url === "/loader.html") { res.setHeader("content-type", "text/html"); res.end(loader); }
    else { res.statusCode = 404; res.end("Not found"); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return {
    args: ["--ignore-certificate-errors", "--no-proxy-server", `--host-resolver-rules=MAP artifacts.private-agent.dstack.soc1024.com 127.0.0.1:${server.address().port},MAP private-agent.dstack.soc1024.com 127.0.0.1:${server.address().port}`],
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true }); },
  };
}
