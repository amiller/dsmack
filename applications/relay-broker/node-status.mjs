import { unhex } from "../../dstack-compat/secret-release/policy.mjs";
import { canonicalFleet } from "./fleet.mjs";

export async function nodeStatus(registration, now) {
  if (registration.telemetry === undefined) return undefined;
  const { signature, ...status } = registration.telemetry;
  const need = ok => { if (!ok) throw Error("node telemetry signature/fields"); };
  need(status.relay_peer === registration.relay_peer && typeof status.busy === "boolean" &&
    Number.isSafeInteger(status.jobs_served) && status.jobs_served >= 0 &&
    Number.isSafeInteger(status.updated_at) && Math.abs(now - status.updated_at) <= 60 &&
    (status.last_error === null || typeof status.last_error === "string" && status.last_error.length <= 4096) &&
    /^[0-9a-f]{128}$/.test(signature) && /^[0-9a-f]{64}$/.test(registration.receipt_key));
  const key = await crypto.subtle.importKey("raw", unhex(registration.receipt_key), "Ed25519", false, ["verify"]);
  need(await crypto.subtle.verify("Ed25519", key, unhex(signature),
    new TextEncoder().encode("dsmack-node-status/1\n" + canonicalFleet(status))));
  return { ...status, signature };
}
