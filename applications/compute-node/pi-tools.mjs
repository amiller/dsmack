// Import the package's actual tool factories without loading its CLI/session manager.
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const dist = dirname(fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent")));
const load = (name) => import(pathToFileURL(join(dist, "core", name)).href);
export const { createBashTool, createLocalBashOperations, bashToolSystemPromptContribution } = await load("tools/bash.js");
export const { createReadTool, readToolSystemPromptContribution } = await load("tools/read.js");
export const { createWriteTool, writeToolSystemPromptContribution } = await load("tools/write.js");
export const { createEditTool, editToolSystemPromptContribution } = await load("tools/edit.js");
export const { buildSystemPrompt, buildSystemPromptSections } = await load("system-prompt.js");
export const piVersion = "1.4.0";
export function toolCatalog() {
  return [createBashTool, createReadTool, createWriteTool, createEditTool].map((create) => {
    const { name, label, description, parameters } = create("/workspace");
    return { name, label, description, inputSchema: parameters };
  });
}
export const promptContributions = {
  bash: bashToolSystemPromptContribution,
  read: readToolSystemPromptContribution,
  write: writeToolSystemPromptContribution,
  edit: editToolSystemPromptContribution,
};
