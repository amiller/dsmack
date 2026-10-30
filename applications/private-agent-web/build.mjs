import { build } from "esbuild";
import { generateManifest } from "./bridge/generate.mjs";
import { piPromptPlugin } from "../compute-node/pi-browser-build.mjs";
import { copyFile, cp, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const app = dirname(fileURLToPath(import.meta.url));
const pi = resolve(app, "node_modules/@earendil-works/pi-web-ui/dist");
await generateManifest();
await mkdir(resolve(app, "dist"), { recursive: true });
await build({
  absWorkingDir: app,
  plugins: [piPromptPlugin()],
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
for (const name of ["index.html", "style.css", "config.json"]) {
  await copyFile(resolve(app, name), resolve(app, "dist", name));
}
await copyFile(resolve(pi, "app.css"), resolve(app, "dist/pi.css"));
// The public network view is dependency-free and shares this IPFS release.
const { copyDashboard } = await import("../network-dashboard/build.mjs");
await copyDashboard(resolve(app, "dist/network"));
await import("../operator-fleet/build.mjs");
await cp(resolve(app, "../operator-fleet/dist"), resolve(app, "dist/fleet"), { recursive: true });
