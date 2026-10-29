import { Wallet } from "../payments/schema.mjs";
import { signingKey } from "./grants.mjs";

// Shared webhost handlers use the project-scoped broker socket. The proxy
// constructs the GetKey path from this project's identity and the safe name.
export async function getSigningKey(socket = "/run/broker/relay-broker/dstack.sock", paid = false) {
  using client = Deno.createHttpClient({ proxy: { transport: "unix", path: socket } });
  const name = paid ? "payments-grants-v1" : "egress-grants-v1";
  const response = await fetch("http://localhost/GetKey", {
    client, method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, algorithm: paid ? "secp256k1" : "ed25519",
      path: "/tee-daemon/projects/relay-broker/" + name, purpose: paid ? "dsmack-payments-grants/1" : "dsmack-egress-grants/1" }),
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error("dstack GetKey failed: HTTP " + response.status);
  const { key } = await response.json();
  return paid ? new Wallet("0x" + key.replace(/^0x/, "")) : signingKey(key);
}
