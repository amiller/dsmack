import { build } from "esbuild";
import { copyFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const app = dirname(fileURLToPath(import.meta.url));
const pi = resolve(app, "node_modules/@mariozechner/pi-web-ui/dist");
const sandboxSource = process.env.SANDBOX_SOURCE ||
  resolve(app, "../compute-node/browser/sandbox.mjs");
await mkdir(resolve(app, "dist"), { recursive: true });
await build({
  absWorkingDir: app,
  entryPoints: { app: "app.mjs", "sandbox-client": sandboxSource },
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  outdir: "dist",
  alias: {
    "npm:ethers@6.17.0": "ethers",
    "@sandbox": sandboxSource,
    "@pi-components": pi,
  },
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "info",
});
for (const name of ["index.html", "style.css", "config.json"]) {
  await copyFile(resolve(app, name), resolve(app, "dist", name));
}
await copyFile(resolve(pi, "app.css"), resolve(app, "dist/pi.css"));
