import { mkdir, copyFile, readFile, writeFile, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const app = dirname(fileURLToPath(import.meta.url));
export async function copyDashboard(target) {
  const dependencies = resolve(process.env.WEB_NODE_MODULES || resolve(app, "../private-agent-web/node_modules"));
  const { build } = await import(pathToFileURL(resolve(dependencies, "esbuild/lib/main.js")));
  const result = await build({ absWorkingDir: app, entryPoints: ["app.mjs"], bundle: true, format: "esm", platform: "browser", target: "es2022", minify: true, write: false, legalComments: "none" });
  const script = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
  const hash = createHash("sha256").update(script).digest("base64");
  const css = await readFile(resolve(app, "style.css"), "utf8");
  const html = (await readFile(resolve(app, "index.html"), "utf8"))
    .replace("script-src 'self'", `script-src 'sha256-${hash}'`)
    .replace('<link rel="stylesheet" href="./style.css">', () => `<style>${css}</style>`)
    .replace('<script type="module" src="./app.mjs"></script>', () => `<script type="module">${script}</script>`);
  await mkdir(target, { recursive: true });
  await writeFile(resolve(target, "index.html"), html);
  await copyFile(resolve(app, "config.json"), resolve(target, "config.json"));
  for (const file of ["style.css", "app.mjs", "chain.mjs"]) await rm(resolve(target, file), { force: true });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await copyDashboard(process.argv[2] ? resolve(process.argv[2]) : resolve(app, "dist"));
