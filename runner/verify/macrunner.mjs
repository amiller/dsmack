// Verifies a runner /attest response (notes/abalone-node-interface.md item 1) for abalone's /abalone/attest/1.
// Uses the documented vendored Abalone App Attest verifier: pinned Apple root, Mac key ACL, app id,
// validation category, and the CDHash allowlist on the enrollment AND on the assertion.
import { verifyAssertion, verifyAttestation } from "./vendor/appattest.mjs";

const APP_ID = "DC9JH5DRMY.dev.dsmack.provider";  // the dsmack bundle Runner.app is signed as (runner/sign.sh)
const MAC_CATEGORY = 3;
const must = (ok, reason) => { if (!ok) throw new Error(`✗ refused: Mac runner: ${reason}`); };

// ev: the /attest JSON. cdhashes, composeHashes: admitted hex values. expectData: the exact assertClientData.data,
// `abalone-attest/1|<peerId>|<remotePeerId>|<nonce>`. The runner re-enrolls every 6 h; older enrollments are refused.
export function verifyMacRunner(ev, { cdhashes, composeHashes, expectData, maxAgeSeconds = 12 * 3600, now = new Date() }) {
  must(ev.type === "macrunner", `evidence type ${ev.type} is not macrunner`);
  const policy = { appId: APP_ID, cdhashes, category: MAC_CATEGORY };
  const enrollBytes = Buffer.from(ev.bootClientData, "base64"), assertBytes = Buffer.from(ev.assertClientData, "base64");
  const a = verifyAttestation(Buffer.from(ev.attestation, "base64"), ev.keyId, enrollBytes, policy, now);
  const enroll = JSON.parse(enrollBytes);
  must(["mac-compose-boot/1", "mac-compose-enroll/1"].includes(enroll.domain) && enroll.attested === true, `enrollment domain ${enroll.domain}`);
  must(composeHashes.includes(enroll.compose_hash), `compose_hash ${enroll.compose_hash} is not admitted`);
  const age = now.getTime() / 1000 - enroll.enrolled_at;
  must(age >= -60 && age <= maxAgeSeconds, `enrollment age ${age} s is outside [0, ${maxAgeSeconds}]`);
  const s = verifyAssertion(Buffer.from(ev.assertion, "base64"), assertBytes, a.publicKey, policy);
  must(s.cdhash === a.cdhash, "assertion CDHash differs from the enrollment's");
  const asserted = JSON.parse(assertBytes);
  must(asserted.domain === "mac-compose-assert/1", `assertion domain ${asserted.domain}`);
  must(asserted.compose_hash === enroll.compose_hash, "assertion compose_hash differs from the enrollment's");
  must(asserted.data === expectData, "assertion data is not what this verifier asked for");
  return { cdhash: a.cdhash, compose_hash: enroll.compose_hash };
}
