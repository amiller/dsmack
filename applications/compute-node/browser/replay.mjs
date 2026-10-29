// Replay an operator-selected real evidence fixture; input paths never enter the page bundle.
import fs from "node:fs";
import assert from "node:assert/strict";
import {
  canonical,
  hex,
  unhex,
  verifyJobAttestation,
  verifyNode,
  verifyReceipt,
  verifyTurnOutputs,
} from "./sandbox.mjs";
import { APP_ID, verifyEnrollment } from "./enrollment.mjs";
import { sha256 } from "../../../dstack-compat/secret-release/policy.mjs";
import {
  domain,
  paymentBinding,
  paymentRunId,
  Receipt,
  verifyTypedData,
} from "./payments.mjs";
import { TypedDataEncoder } from "./vendor/ethers-6.17.0.mjs";
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const read = (p) => new Uint8Array(fs.readFileSync(p)),
  json = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const registration = json(cfg.discovery),
  manifest = read(cfg.manifest),
  enrollment = {
    attestation: read(cfg.enrollment + "/attestation.cbor"),
    keyId: fs.readFileSync(cfg.enrollment + "/keyId.txt", "utf8").trim(),
    clientData: read(cfg.enrollment + "/clientData.bin"),
  };
const e = await verifyEnrollment(enrollment, registration.cdhash);
// This historical replay supplies a chain snapshot; live browser tests use RPC.
const chain = {
  key: async () => ({
    x: e.point.slice(1, 33),
    y: e.point.slice(33),
    enrolled: true,
    expires: e.expires / 1000,
    counter: 0,
  }),
  category: async () => 3,
  rpIdHash: async () => sha256(new TextEncoder().encode(APP_ID)),
  burnedImage: async () => false,
  burnedBuild: async () => false,
  buildId: async () => new Uint8Array(32),
};
const brokerKey =
  JSON.parse(JSON.parse(new TextDecoder().decode(manifest)).docker_compose_file)
    .services.node.command[4];
const policy = {
  manifest,
  enrollment,
  cdhash: registration.cdhash,
  brokerKey,
  chain,
};
const node = await verifyNode(registration, policy),
  result = json(cfg.result),
  grant = json(cfg.grant),
  sealed = json(cfg.sealed),
  job = {
    node,
    jobId: result.statement.job_id,
    grant,
    sealed,
    client: { peer: result.receipt.client_peer },
  };
await verifyJobAttestation(node, result, job);
await verifyReceipt(node, result, job);
await verifyTurnOutputs(
  node,
  Object.fromEntries(
    ["patch", "transcript", "verdict"].map(
      (name) => [name, read(cfg.outputs + "/" + name)],
    ),
  ),
);
for (const name of ["patch", "transcript", "verdict"]) {
  assert.equal(
    hex(await sha256(read(cfg.outputs + "/" + name))),
    result.statement.outputs[name],
  );
}
await assert.rejects(
  verifyNode({ ...registration, receipt_key: "00".repeat(32) }, policy),
  /binding/,
);
await assert.rejects(
  verifyNode(registration, { ...policy, brokerKey: "00".repeat(32) }),
  /broker key/,
);
const wrongManifest = JSON.parse(new TextDecoder().decode(manifest));
wrongManifest.base_vm.os_image_hash = "00".repeat(32);
await assert.rejects(
  verifyNode(registration, { ...policy, manifest: canonical(wrongManifest) }),
  /measurements/,
);
await assert.rejects(
  verifyReceipt(node, {
    ...result,
    receipt: { ...result.receipt, job_id: "00".repeat(16) },
  }, job),
  /signature/,
);
if (cfg.paidDiscovery && cfg.paidPolicy) {
  const d = json(cfg.paidDiscovery), raw = json(cfg.paidPolicy);
  const p = {
    ...raw,
    manifest: unhex(raw.manifest),
    enrollment: {
      ...raw.enrollment,
      attestation: unhex(raw.enrollment.attestation),
      clientData: unhex(raw.enrollment.clientData),
    },
  };
  const enrolled = await verifyEnrollment(p.enrollment, p.cdhash);
  p.challenge = d.payments.challenge;
  p.chain = {
    ...chain,
    key: async () => ({
      x: enrolled.point.slice(1, 33),
      y: enrolled.point.slice(33),
      enrolled: true,
      expires: enrolled.expires / 1000,
      counter: 0,
    }),
    buildId: async () => unhex(d.payments.buildId.slice(2)),
  };
  const original = Date.now;
  Date.now = () => (d.payments.runExpires - 100) * 1000;
  try {
    await verifyNode(d, p);
  } finally {
    Date.now = original;
  }
}
if (cfg.paymentsFixture) {
  const f = json(cfg.paymentsFixture);
  assert.equal(
    paymentRunId(f.registration.enrollmentKeyId, f.registration.runNonce),
    f.registration.runId,
  );
  assert.equal(
    paymentBinding(f.registration, f.peer, "00".repeat(32), "00".repeat(32)),
    f.binding,
  );
  assert.equal(
    verifyTypedData(
      domain(f.escrow),
      { Receipt },
      f.receipt.receipt,
      f.receipt.signature,
    ).toLowerCase(),
    f.registration.receiptSigner.toLowerCase(),
  );
  assert.equal(
    TypedDataEncoder.hash(domain(f.escrow), { Receipt }, f.receipt.receipt),
    f.receiptDigest,
  );
}
console.log(JSON.stringify({
  apple_chain: "passed",
  ...(cfg.paidDiscovery ? { real_paid_registration: "passed" } : {}),
  ...(cfg.paymentsFixture ? { go_payment_binding_and_receipt: "passed" } : {}),
  node_binding: "passed",
  job_attestation: "passed",
  receipt: "passed",
  plaintext_hashes: "passed",
  transcript_verdict: "passed",
  wrong_receipt_key: "refused",
  wrong_broker_key: "refused",
  swapped_image: "refused",
  changed_receipt: "refused",
  run: node.run,
  counter: node.counter,
  result_counter: (await verifyJobAttestation(node, result, job)).counter,
}));
