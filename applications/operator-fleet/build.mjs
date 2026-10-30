import { mkdir, copyFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const app = dirname(fileURLToPath(import.meta.url));
const dependencies = resolve(process.env.WEB_NODE_MODULES || resolve(app, "../private-agent-web/node_modules"));
const { build } = await import(pathToFileURL(resolve(dependencies, "esbuild/lib/main.js")));
await mkdir(resolve(app, "dist"), { recursive: true });
await build({ absWorkingDir: app, entryPoints: ["app.mjs"], bundle: true, format: "esm", platform: "browser", target: "es2022", minify: true, outdir: "dist", nodePaths: [dependencies], alias: { "npm:ethers@6.17.0": resolve(dependencies, "ethers/lib.esm/index.js") } });
for (const name of ["index.html", "style.css", "config.json"]) await copyFile(resolve(app, name), resolve(app, "dist", name));
