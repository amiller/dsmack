// Image provenance checks query rekor.sigstore.dev.
import { strict as assert } from "node:assert";
import { checkComposeBinding, checkImages, checkOs } from "./near-policy.mjs";

const load = async (path) => JSON.parse(await Deno.readTextFile(new URL(path, import.meta.url)));
const reports = {
  f571e5da: await load("../private-agent-web/test-fixtures/near/report.json"),
  c579aade: await load("./fixtures/near-report-20261104.json"),
};
const compose = (a) => (typeof a.info.tcb_info === "string" ? JSON.parse(a.info.tcb_info) : a.info.tcb_info).app_compose;
const attestations = (r) => [["gateway", r.gateway_attestation], ...r.model_attestations.map((m) => ["model", m])];
async function check(tier, a, appCompose = compose(a)) {
  checkOs(tier, a.intel_quote);
  if (a.compose_manager_attestation) checkOs(tier, a.compose_manager_attestation.quote);
  await checkComposeBinding(appCompose, a.intel_quote);
  await checkImages(tier, appCompose);
}

for (const [gateway, report] of Object.entries(reports)) {
  Deno.test(`NEAR gateway ${gateway} and its model satisfy the teep policy`, async () => {
    assert.equal(report.gateway_attestation.info.compose_hash.slice(0, 8), gateway);
    for (const [tier, a] of attestations(report)) await check(tier, a);
  });
}

Deno.test("an unlisted image, an unbound compose or another tier's OS is rejected", async () => {
  const gw = reports.c579aade.gateway_attestation, appCompose = compose(gw);
  const parsed = JSON.parse(appCompose);
  parsed.docker_compose_file += "\n  extra:\n    image: example/unlisted@sha256:" + "ab".repeat(32) + "\n";
  const tampered = JSON.stringify(parsed);
  await assert.rejects(() => checkImages("gateway", tampered), /example\/unlisted is not an approved gateway image/);
  await assert.rejects(() => checkComposeBinding(tampered, gw.intel_quote), /MRCONFIGID/);
  parsed.docker_compose_file = parsed.docker_compose_file.replace(/@sha256:ab+/, ":latest");
  await assert.rejects(() => checkImages("gateway", JSON.stringify(parsed)), /image without digest/);
  await assert.rejects(() => checkImages("model", appCompose), /not an approved model image/);
  assert.throws(() => checkOs("model", gw.intel_quote), /unknown model mrtd/);
});

Deno.test("a Rekor entry with a forged timestamp or proof is rejected", async () => {
  const appCompose = compose(reports.c579aade.gateway_attestation);
  for (const [field, pattern] of [["signedEntryTimestamp", /Rekor SET/], ["rootHash", /inclusion proof root/]]) {
    const fresh = await import(`./near-policy.mjs?${field}`);
    const forging = async (url, init) => {
      const r = await fetch(url, init);
      if (!String(url).endsWith("/entries/retrieve")) return r;
      const entries = await r.json();
      for (const e of entries.flatMap(Object.values)) {
        if (field === "rootHash") e.verification.inclusionProof.rootHash = "00".repeat(32);
        else e.verification.signedEntryTimestamp = reports.c579aade.gateway_attestation.intel_quote.slice(0, 96);
      }
      return Response.json(entries);
    };
    await assert.rejects(() => fresh.checkImages("gateway", appCompose, forging), pattern);
  }
});
