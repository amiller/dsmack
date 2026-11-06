import test from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { piPromptPlugin } from "../compute-node/pi-browser-build.mjs";

const bundled = await build({
  entryPoints: [new URL("./pi-prompt.mjs", import.meta.url).pathname],
  plugins: [piPromptPlugin()], bundle: true, format: "esm", platform: "browser", write: false,
});
const { buildAgentPrompt } = await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`);

test("network prompt points curl at the configured broker and current page config", () => {
  for (const [broker, pageUrl, configUrl] of [
    ["https://broker.example/relay-broker", "https://broker.example/private-agent/", "https://broker.example/private-agent/config.json"],
    ["https://staging.example/relay-broker-staging", "https://staging.example/private-agent-staging/?chat=1#key", "https://staging.example/private-agent-staging/config.json"],
    ["https://broker.example/relay-broker-staging", "https://page.example/", "https://page.example/config.json"],
  ]) {
    const prompt = buildAgentPrompt({ config: { broker }, pageUrl });
    assert.ok(prompt.includes(`curl ${broker}/network`));
    assert.ok(prompt.includes(`curl ${configUrl}`));
  }
});
