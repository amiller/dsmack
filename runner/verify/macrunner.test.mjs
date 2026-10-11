// Laptop check of macrunner.mjs against the recorded signed boot in fixtures/attested-20261008T145504 (pre-/attest:
// it has an enrollment but no assertion and no enrolled_at). usage: node verify/macrunner.test.mjs
import fs from "node:fs";
import { verifyMacRunner } from "./macrunner.mjs";

const d = new URL("./fixtures/attested-20261008T145504/", import.meta.url);
const read = (f) => fs.readFileSync(new URL(f, d));
const CDH = "d2a0b9295a6d1583c1759b3b461f5842d96c83fdcdde9a4b15daaa5a9bb6e5ce";
const COMPOSE = JSON.parse(read("clientData.bin")).compose_hash;
const ev = { type: "macrunner", attestation: read("attestation.cbor").toString("base64"), keyId: read("keyId.txt").toString().trim(),
  bootClientData: read("clientData.bin").toString("base64"), assertion: "", assertClientData: "" };
const opts = { cdhashes: [CDH], composeHashes: [COMPOSE], expectData: "x", now: new Date("2026-10-08T19:00:00Z") };
const refusal = (o) => { try { verifyMacRunner(...o); return "accepted"; } catch (e) { return e.message; } };
const cases = [
  ["dev evidence refused", [{ ...ev, type: "dev" }, opts], /evidence type dev/],
  ["other CDHash refused at the attestation", [ev, { ...opts, cdhashes: ["00".repeat(32)] }], /is not admitted/],
  ["other compose refused", [ev, { ...opts, composeHashes: ["00".repeat(32)] }], /compose_hash .* is not admitted/],
  ["tampered clientData refused", [{ ...ev, bootClientData: Buffer.from(read("clientData.bin").toString().replace("true", "false ")).toString("base64") }, opts], /nonce does not bind/],
  // The real attestation passes; this pre-re-enrollment capture has no enrolled_at, so the age check refuses it.
  ["real attestation passes, then no enrolled_at refused", [ev, opts], /enrollment age NaN/],
];
let failed = 0;
for (const [name, args, want] of cases) { const got = refusal(args); const ok = want.test(got); failed += !ok; console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${got}`); }
console.log(`FAILED=${failed}`); process.exit(failed);
