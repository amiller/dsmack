import { createServer, connect } from "node:net";

// Loopback forwarder to the operator CONNECT proxy that attaches the stay's browse token, so tools that
// cannot send proxy credentials (Chromium) still get the stay's policy. Without a token the proxy applies
// mode none: operator and package hosts only.
export function browseForwarder(upstream, token, port = 18480) {
  const { hostname, port: upstreamPort } = new URL(upstream);
  const server = createServer((client) => {
    let head = Buffer.alloc(0);
    const onData = (chunk) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf("\r\n\r\n");
      if (end < 0) { if (head.length > 8192) client.destroy(); return; }
      client.pause(); client.off("data", onData);
      const lines = head.subarray(0, end).toString("latin1").split("\r\n").filter((line) => !/^proxy-authorization:/i.test(line));
      if (token()) lines.push("Proxy-Authorization: Basic " + Buffer.from("browse:" + token()).toString("base64"));
      const proxy = connect(Number(upstreamPort), hostname, () => {
        proxy.write(Buffer.concat([Buffer.from(lines.join("\r\n") + "\r\n\r\n", "latin1"), head.subarray(end + 4)]));
        client.pipe(proxy); proxy.pipe(client);
      });
      proxy.on("error", () => client.destroy()); client.on("error", () => proxy.destroy());
    };
    client.on("data", onData);
  });
  return new Promise((done, fail) => { server.once("error", fail); server.listen(port, "127.0.0.1", () => done(server)); });
}

export async function browsePolicy(port = 18480) {
  const response = await fetch(`http://127.0.0.1:${port}/browse`, { signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`browse policy HTTP ${response.status}`);
  return response.json();
}
