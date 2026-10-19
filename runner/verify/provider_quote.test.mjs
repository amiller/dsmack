// On-chain admission in provider_quote.mjs, against live Base and the recorded NEAR report in test/near-report-20261008.json
// (no API key needed: it checks compose measurement and admission, not the quote or nonce). usage: node verify/provider_quote.test.mjs
import fs from "node:fs";
import { admit, allowed, chainAt, keccak256, nearEvidence } from "./provider_quote.mjs";

const src = fs.readFileSync(new URL("../Sources/runner/Anchors.swift", import.meta.url), "utf8");
const anchors = [...src.matchAll(/^ {4}"([A-Za-z0-9+/=]+)",$/gm)].map((m) => m[1]);
const amazonOnly = anchors.filter((a) => a.startsWith("MIIDQTCCAimgAwIBAgITBmyfz5m"));
const rep = JSON.parse(fs.readFileSync(new URL("../test/near-report-20261008.json", import.meta.url)));
const GW = "0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae", MODELS = "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b";
const RPC = "https://mainnet.base.org", onchain = { rpc: RPC, apps: [GW, MODELS] };
const chain = await chainAt(onchain, anchors);
const gw = nearEvidence(rep.gateway_attestation), model = nearEvidence(rep.model_attestations[0]);
const result = async (f) => { try { return JSON.stringify(await f()); } catch (e) { return `refused: ${e.message}`; } };
const cases = [
  ["selector is cast sig", () => "0x" + keccak256(Buffer.from("allowedComposeHashes(bytes32)")).subarray(0, 4).toString("hex"), /^"0x2f6622e5"$/],
  ["block is recent", () => chain.block, /^[0-9]{8,}$/],
  ["gateway compose allowed on its app", () => allowed(chain, GW, "8bc802c9c8043a9c21d1face81b9c9381ed621644478e0b7f5a7f81a7230b1fa"), /^true$/],
  ["model compose allowed on its app", () => allowed(chain, MODELS, "c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86"), /^true$/],
  ["random compose not allowed", () => allowed(chain, GW, "11".repeat(32)), /^false$/],
  ["recorded gateway admitted by its app", () => admit(gw, "gateway", { onchain }, chain), new RegExp(`"app":"${GW}"`)],
  ["recorded model admitted by its app", () => admit(model, "model", { onchain }, chain), new RegExp(`"app":"${MODELS}"`)],
  ["app_id not in apps refused", () => admit(gw, "gateway", { onchain: { rpc: RPC, apps: [MODELS] } }, chain), /measured app-id 0xf550.* is not in onchain.apps/],
  // 55db164f… was not yet allowed on the models app at block 51000000 (cast call --block, 2026-10-08).
  ["compose not allowed at that block refused", () => admit(model, "model", { onchain }, { ...chain, hex: "0x30a32c0", block: 51000000 }),
    /compose-hash 55db164f.* is not allowed by DstackApp 0x2c0a.* at block 51000000/],
  ["tampered app-id payload refused", () => admit({ attestation: { evidence: { ...gw.attestation.evidence, event_log: gw.attestation.evidence.event_log.replace("f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae", MODELS.slice(2)) } } }, "gateway", { onchain }, chain), /app-id event payload does not match its digest/],
  ["non-contract app refused (empty eth_call result)", () => allowed(chain, "0x" + "00".repeat(19) + "01", "11".repeat(32)), /returned 0x$/],
  ["RPC error refused", () => allowed({ ...chain, hex: "0x" + (chain.block + 1e6).toString(16) }, GW, "11".repeat(32)), /refused: provider quote refused: RPC eth_call: /],
  ["RPC TLS root not anchored refused", () => chainAt(onchain, amazonOnly), /refused: .*(certificate|issuer)/],
  ["non-https RPC refused", () => chainAt({ rpc: "http://mainnet.base.org", apps: [] }, anchors), /is not https/],
];
let failed = 0;
for (const [name, f, want] of cases) { const got = await result(f); const ok = want.test(got); failed += !ok; console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${got.slice(0, 200)}`); }
console.log(`FAILED=${failed}`); process.exit(failed);
