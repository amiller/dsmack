import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { build } from "esbuild";
import { chromium, firefox } from "playwright";
import { nearRequestBodyPlugin } from "./near-browser-build.mjs";

const bundled = await build({
  stdin: {
    resolveDir: import.meta.dirname,
    contents: `import { prepareE2eeChatRequest } from "@nearai/inference-sdk";
      window.encrypt = async (prompt) => {
        const prepared = await prepareE2eeChatRequest({
          request: new Request("https://cloud-api.near.ai/v1/chat/completions", {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({model:"test/model", messages:[{role:"user", content:prompt}], stream:true}),
          }),
          modelKey: { signingAlgo:"ecdsa", publicKey:
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8" },
        });
        return {body:await prepared.request.json(), headers:Object.fromEntries(prepared.request.headers)};
      };`,
  },
  bundle: true, write: false, format: "esm", platform: "browser",
  plugins: [nearRequestBodyPlugin()],
});
for (const [engine, launcher] of Object.entries({ chromium, firefox })) {
  test(`${engine} encrypts ASCII, Unicode and near-limit bodies without Request.body`, async () => {
    const server = createServer((req, res) => {
      res.setHeader("Content-Type", req.url === "/sdk.js" ? "text/javascript" : "text/html");
      res.end(req.url === "/sdk.js" ? bundled.outputFiles[0].contents : '<!doctype html><script type="module" src="/sdk.js"></script>');
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    let browser;
    try {
      browser = await launcher.launch({ headless: true });
      const page = await browser.newPage({ locale: "fr-FR" });
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      await page.waitForFunction(() => typeof window.encrypt === "function");
      for (const prompt of ["Reply OK.", "Emoji 😀 CJK 中文 narrow space:\u202fend.", "a".repeat(129500)]) {
        const result = await page.evaluate(prompt => window.encrypt(prompt), prompt);
        assert.equal(result.body.model, "test/model");
        assert.match(result.body.messages[0].content, /^04[0-9a-f]+$/i);
        assert(result.body.messages[0].content.length > new TextEncoder().encode(prompt).length * 2);
        assert.equal(result.headers["x-encrypt-all-fields"], "true");
        assert.equal(result.headers["content-length"], undefined);
      }
    } finally {
      await browser?.close();
      await new Promise(resolve => server.close(resolve));
    }
  });
}
