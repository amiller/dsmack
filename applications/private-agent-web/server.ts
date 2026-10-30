import { tunnelIndex } from "../relay-broker/tunnel-index.mjs";
const root = new URL("./dist/", import.meta.url);
const types: Record<string, string> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  mjs: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  json: "application/json; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  webp: "image/webp",
  ico: "image/x-icon",
  woff2: "font/woff2",
};
const security = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' https://pod.dstack.soc1024.com https://sepolia.base.org https://base-sepolia-rpc.publicnode.com https://base-sepolia.drpc.org; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};

// The shared webhost router strips /private-agent before invoking this handler.
export default async function handler(req: Request,ctx?: {env:Record<string,string>}) {
  if(new URL(req.url).pathname==="/tunnels")return await tunnelIndex(req,ctx?.env.OPERATOR_TOKEN_SHA256);
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { ...security, allow: "GET, HEAD" },
    });
  }
  let path: string;
  try {
    path = decodeURIComponent(new URL(req.url).pathname);
  } catch {
    return new Response("Invalid path", { status: 400, headers: security });
  }
  const parts = path.split("/").filter(Boolean);
  if (parts.some((part) => part.startsWith(".") || /[\\\0]/.test(part))) {
    return new Response("Invalid path", { status: 400, headers: security });
  }
  const file = parts.length ? parts.join("/") : "index.html";
  const type = types[file.split(".").pop() ?? ""];
  if (!type) {
    return new Response("Not found", { status: 404, headers: security });
  }
  try {
    const bytes = await Deno.readFile(
      new URL(file.split("/").map(encodeURIComponent).join("/"), root),
    );
    return new Response(req.method === "HEAD" ? null : bytes, {
      headers: {
        ...security,
        "content-type": type,
        "content-length": String(bytes.length),
      },
    });
  } catch (error) {
    if (
      error instanceof Deno.errors.NotFound ||
      error instanceof Deno.errors.IsADirectory
    ) {
      return new Response("Not found", { status: 404, headers: security });
    }
    throw error;
  }
}

if (import.meta.main) {
  Deno.serve(
    { hostname: "127.0.0.1", port: Number(Deno.args[0] ?? "8788") },
    (req) => handler(req),
  );
}
