import test from "node:test";
import assert from "node:assert/strict";
import { sealArtifact, openArtifact, artifactLink, parseArtifactLink, sharedScope, viewerSessionId, MAX_SHARE_BYTES, cidFor } from "./artifact-share.mjs";
import { encodeBase64Url, decodeBase64Url } from "./content-address.mjs";

test("sharing includes only immutable HTML and its functional manifest, with fresh independent keys", async () => {
  const html = "<html><body>Shared app</body></html>", a = await sealArtifact(html), b = await sealArtifact(html);
  assert.notEqual(a.key, b.key); assert.notEqual(a.cid, b.cid);
  const bundle = await openArtifact(a);
  assert.deepEqual(Object.keys(bundle).sort(), ["html", "manifest", "v"]);
  assert.equal(bundle.html, html);
  assert.equal(bundle.manifest.bridgeVersion, 1);
});
test("the key stays in the fragment and viewer scope cannot reset through reloads or filenames", async () => {
  const sealed = await sealArtifact("<body>Hello</body>"), url = new URL(artifactLink(sealed));
  assert.equal(url.pathname, "/a/"); assert.equal(url.search, "");
  assert.deepEqual(parseArtifactLink(url.href), { cid: sealed.cid, key: sealed.key });
  assert.equal(sharedScope(sealed.cid), JSON.stringify(["shared", sealed.cid]));
  assert.equal(viewerSessionId("0xABC", sealed.cid), viewerSessionId("0xabc", sealed.cid));
  assert.notEqual(viewerSessionId("0xabc", sealed.cid), viewerSessionId("0xdef", sealed.cid));
});
test("CID mismatch, wrong keys and authenticated malformed bundles are rejected before rendering", async () => {
  const sealed = await sealArtifact("<body>test</body>"), bytes = decodeBase64Url(sealed.ciphertext);
  bytes[15] ^= 1;
  await assert.rejects(openArtifact({ ...sealed, ciphertext: encodeBase64Url(bytes) }), /CID mismatch/);
  await assert.rejects(openArtifact({ ...sealed, key: (await sealArtifact("other")).key }));
  const nonce = crypto.getRandomValues(new Uint8Array(12)), raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce,
    additionalData: new TextEncoder().encode("dsmack-artifact-share-v1") }, key,
  new TextEncoder().encode(JSON.stringify({ v: 1, html: "test", manifest: {}, storage: { secret: "not code" } }))));
  const invalid = new Uint8Array(12 + encrypted.length); invalid.set(nonce); invalid.set(encrypted, 12);
  await assert.rejects(openArtifact({ cid: await cidFor(invalid), ciphertext: encodeBase64Url(invalid), key: encodeBase64Url(raw) }), /Invalid shared artifact/);
  await assert.rejects(sealArtifact("x".repeat(MAX_SHARE_BYTES)), /512 KiB/);
});
