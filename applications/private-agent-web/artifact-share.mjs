import { cidFor, encodeBase64Url, decodeBase64Url } from "./content-address.mjs";
import bridge from "./bridge/Manifest.json" with { type: "json" };
export { cidFor };
export const MAX_SHARE_BYTES = 512 * 1024;
const aad = new TextEncoder().encode("dsmack-artifact-share-v1");
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).sort().join() === fields.sort().join();
const capability = name => bridge.methods.some(method => method.name === name);
const need = (ok, message) => { if (!ok) throw new Error(message); };
export const isArtifactCid = value => typeof value === "string" && /^bafkrei[a-z2-7]{52}$/.test(value);
export const functionalManifest = () => ({ bridgeVersion: 1, requiredCapabilities: [],
  optionalCapabilities: ["storage.get", "storage.put", "storage.list", "agent.complete", "credit.balance", "diagnostics.log"] });

function validate(bundle) {
  need(exact(bundle, ["v", "html", "manifest"]) && bundle.v === 1 && typeof bundle.html === "string" && bundle.html.length > 0,
    "Invalid shared artifact bundle.");
  const manifest = bundle.manifest;
  need(exact(manifest, ["bridgeVersion", "requiredCapabilities", "optionalCapabilities"]) && manifest.bridgeVersion === 1 &&
    [manifest.requiredCapabilities, manifest.optionalCapabilities].every(names => Array.isArray(names) && names.length <= 32 && names.every(capability)),
    "Invalid shared artifact manifest.");
  return bundle;
}
export async function sealArtifact(html, manifest = functionalManifest()) {
  const bundle = validate({ v: 1, html, manifest });
  const plain = new TextEncoder().encode(JSON.stringify(bundle));
  need(plain.length + 28 <= MAX_SHARE_BYTES, "Shared artifact exceeds 512 KiB.");
  const rawKey = crypto.getRandomValues(new Uint8Array(32)), nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plain));
  const bytes = new Uint8Array(12 + encrypted.length); bytes.set(nonce); bytes.set(encrypted, 12);
  return { cid: await cidFor(bytes), ciphertext: encodeBase64Url(bytes), key: encodeBase64Url(rawKey) };
}
export async function openArtifact({ cid, ciphertext, key: keyText }) {
  need(isArtifactCid(cid), "Invalid artifact CID.");
  need(typeof ciphertext === "string" && ciphertext.length <= Math.ceil(MAX_SHARE_BYTES * 4 / 3) && /^[A-Za-z0-9_-]+$/.test(ciphertext), "Invalid artifact ciphertext.");
  const bytes = decodeBase64Url(ciphertext);
  need(bytes.length >= 29 && bytes.length <= MAX_SHARE_BYTES && await cidFor(bytes) === cid, "Shared artifact ciphertext CID mismatch.");
  need(typeof keyText === "string" && /^[A-Za-z0-9_-]{43}$/.test(keyText), "Invalid artifact link key.");
  const rawKey = decodeBase64Url(keyText);
  need(rawKey.length === 32, "Invalid artifact link key.");
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: aad }, key, bytes.slice(12));
  return validate(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain)));
}
export function artifactLink({ cid, key }) {
  return "https://private-agent.dstack.soc1024.com/a/#" + new URLSearchParams({ cid, k: key });
}
export function parseArtifactLink(url) {
  const parsed = new URL(url);
  if (!/\/a\/?$/.test(parsed.pathname)) return null;
  const params = new URLSearchParams(parsed.hash.slice(1)), cid = params.get("cid"), key = params.get("k");
  need(isArtifactCid(cid) && /^[A-Za-z0-9_-]{43}$/.test(key || ""), "This artifact link is incomplete or invalid.");
  return { cid, key };
}
export const sharedScope = cid => JSON.stringify(["shared", cid]);
export const viewerSessionId = (wallet, cid) => `shared-${wallet.toLowerCase().replace(/^0x/, "")}-${cid}`;
