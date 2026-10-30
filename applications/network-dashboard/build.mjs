import { mkdir, copyFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const app = dirname(fileURLToPath(import.meta.url));
export async function copyDashboard(target) {
  await mkdir(target, { recursive: true });
  for (const file of ["index.html", "style.css", "app.mjs", "chain.mjs", "config.json"]) await copyFile(resolve(app, file), resolve(target, file));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await copyDashboard(process.argv[2] ? resolve(process.argv[2]) : resolve(app, "dist"));
