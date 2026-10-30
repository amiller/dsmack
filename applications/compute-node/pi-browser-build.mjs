import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toolCatalog, promptContributions } from "./pi-tools.mjs";

// Bundle the upstream builder itself. Its CLI documentation and skills loader
// are the only Node-specific imports; browser agent mode loads no local skills.
export function piPromptPlugin() {
  const dist = dirname(fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent")));
  return {
    name: "pi-browser-system-prompt",
    setup(build) {
      build.onResolve({ filter: /^@pi-prompt-builder$/ }, () => ({ path: join(dist, "core/system-prompt.js") }));
      build.onResolve({ filter: /^@pi-tools-catalog$/ }, () => ({ path: "catalog", namespace: "pi-prompt-data" }));
      build.onLoad({ filter: /.*/, namespace: "pi-prompt-data" }, () => ({ contents: `export default ${JSON.stringify({ tools: toolCatalog(), contributions: promptContributions })}`, loader: "js" }));
      build.onResolve({ filter: /^(\.\.\/config|\.\/skills)\.js$/ }, (args) => {
        if (args.importer !== join(dist, "core/system-prompt.js")) return;
        return { path: args.path, namespace: "pi-prompt-shim" };
      });
      build.onLoad({ filter: /.*/, namespace: "pi-prompt-shim" }, ({ path }) => ({ contents: path.includes("config")
        ? `export const getReadmePath=()=>"/opt/compute-node/node_modules/@earendil-works/pi-coding-agent/README.md",getDocsPath=()=>"/opt/compute-node/node_modules/@earendil-works/pi-coding-agent/docs",getExamplesPath=()=>"/opt/compute-node/node_modules/@earendil-works/pi-coding-agent/examples";`
        : `export function formatSkillsForPrompt(skills){if(skills.length)throw Error("Browser local skills are unavailable");return "";}`,
        loader: "js" }));
    },
  };
}
