import handler from "./server.ts";

const need = (ok: unknown, message: string) => { if (!ok) throw Error(message); };
const request = (path: string, init?: RequestInit) => handler(new Request("https://agent.test/" + path, init));

Deno.test("documents and config revalidate, while content-addressed assets stay immutable", async () => {
  const index = await request("");
  need(index.headers.get("cache-control") === "no-cache", "Index must revalidate");
  const html = await index.text();
  const assets = [...html.matchAll(/(?:src|href)="\.\/([^"/]+\.[0-9a-f]{16}\.(?:js|css))"/g)].map(match => match[1]);
  need(assets.some(name => name.startsWith("app.")), "Index must reference its hashed app bundle");
  for (const path of [...assets, "config.json"]) {
    const response = await request(path);
    need(response.ok, "Referenced asset must exist: " + path);
    need(response.headers.get("cache-control") === (path === "config.json" ? "no-cache" : "public, max-age=31536000, immutable"), "Incorrect cache policy for " + path);
    const body = new Uint8Array(await response.arrayBuffer());
    if (path !== "config.json") {
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)), b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
      need(path.includes("." + hash + "."), "Asset URL must address its actual content");
    }
  }
});

Deno.test("normal conditional reloads and HEAD preserve validators and cache policy", async () => {
  for (const path of ["", "config.json"]) {
    const first = await request(path);
    const tag = first.headers.get("etag")!;
    const body = await first.arrayBuffer();
    need(/^"[0-9a-f]{64}"$/.test(tag), "Response must carry a strong ETag");
    const unchanged = await request(path, { headers: { "if-none-match": '"older", W/' + tag } });
    need(unchanged.status === 304 && (await unchanged.text()) === "", "Unchanged content must return a bodyless 304");
    need(unchanged.headers.get("etag") === tag && unchanged.headers.get("cache-control") === "no-cache", "304 must retain cache metadata");
    const head = await request(path, { method: "HEAD" });
    need(head.headers.get("etag") === tag && Number(head.headers.get("content-length")) === body.byteLength && (await head.text()) === "", "HEAD must retain representation metadata without a body");
    const changed = await request(path, { headers: { "if-none-match": '"older"' } });
    need(changed.status === 200, "Changed content must return the current representation");
    await changed.body?.cancel();
  }
});
