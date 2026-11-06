import { execFileSync } from "node:child_process";
import { build } from "esbuild";
import { generateManifest } from "./bridge/generate.mjs";
import { nearRequestBodyPlugin } from "./near-browser-build.mjs";
import { piPromptPlugin } from "../compute-node/pi-browser-build.mjs";
import { copyFile, cp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const app = dirname(fileURLToPath(import.meta.url));
const pi = resolve(app, "node_modules/@earendil-works/pi-web-ui/dist");
await generateManifest();
await rm(resolve(app, "dist"), { recursive: true, force: true });
await mkdir(resolve(app, "dist"), { recursive: true });
await build({
  absWorkingDir: app,
  plugins: [piPromptPlugin(), nearRequestBodyPlugin()],
  entryPoints: { app: "app.mjs", "wallet-bootstrap": "wallet-bootstrap.mjs" },
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  outdir: "dist",
  alias: {
    process: "process/browser.js",
    "npm:ethers@6.17.0": "ethers",
    "@sandbox": resolve(app, "../compute-node/browser/sandbox.mjs"),
    "@pi-components": pi,
  },
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "info",
});
await copyFile(resolve(app, "style.css"), resolve(app, "dist/style.css"));
const config = JSON.parse(await readFile(process.env.PAGE_CONFIG || resolve(app, "config.json"), "utf8"));
if (process.env.PAGE_TARGET === "staging") {
  const origin = process.env.PAGE_STAGING_ORIGIN || "https://private-agent-staging.dstack.soc1024.com";
  if (!["https://private-agent-staging.dstack.soc1024.com", "https://pod.dstack.soc1024.com"].includes(origin)) throw new Error("PAGE_STAGING_ORIGIN must be the staging hostname or webhost");
  config.broker = "https://pod.dstack.soc1024.com/relay-broker-staging";
  config.tunnels = origin + (origin === "https://pod.dstack.soc1024.com" ? "/private-agent-staging/tunnels" : "/tunnels");
}
await writeFile(resolve(app, "dist/config.json"), JSON.stringify(config));
await copyFile(resolve(pi, "app.css"), resolve(app, "dist/pi.css"));
let html = await readFile(resolve(app, "index.html"), "utf8");
for (const name of ["app.js", "wallet-bootstrap.js", "style.css", "pi.css"]) {
  const path = resolve(app, "dist", name);
  const hash = createHash("sha256").update(await readFile(path)).digest("hex").slice(0, 16);
  const hashed = name.replace(/\.(js|css)$/, `.${hash}.$1`);
  await rename(path, resolve(app, "dist", hashed));
  html = html.replaceAll(`./${name}`, `./${hashed}`);
}
await writeFile(resolve(app, "dist/index.html"), html);
// The public network view is dependency-free and shares this IPFS release.
const { copyDashboard } = await import("../network-dashboard/build.mjs");
await copyDashboard(resolve(app, "dist/network"));
execFileSync(process.execPath, [resolve(app, "../operator-fleet/build.mjs")], {
  env: { ...process.env, ...(process.env.PAGE_TARGET === "staging" ? { FLEET_CONFIG: resolve(app, "dist/config.json") } : {}) },
  stdio: "inherit",
});
await cp(resolve(app, "../operator-fleet/dist"), resolve(app, "dist/fleet"), { recursive: true });

execFileSync("python3", [resolve(app, "bundle.py"), resolve(app, "dist")], { stdio: "inherit" });
