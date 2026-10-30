import { readFile, writeFile } from "node:fs/promises";
const root = new URL("./", import.meta.url);
export async function generateManifest() {
  const read = async path => JSON.parse(await readFile(new URL(path, root), "utf8"));
  const definition = await read("Definition.json"), methods = [], events = [];
  for (const category of definition.categories) {
    const contract = await read(`Categories/${category}.json`);
    methods.push(...contract.methods); events.push(...contract.events);
  }
  const manifest = { bridgeVersion: definition.bridgeVersion, globalObject: definition.globalObject,
    injectedByApp: definition.injectedByApp, methods, events, errors: definition.errors };
  await writeFile(new URL("Manifest.json", root), JSON.stringify(manifest, null, 2) + "\n");
}
if (import.meta.main || process.argv[1] === new URL(import.meta.url).pathname) await generateManifest();
