import { signingKey } from "./grants.mjs";

// Shared webhost handlers use the project-scoped broker socket. The proxy
// constructs the GetKey path from this project's identity and the safe name.
export async function getSigningKey(socket = "/run/broker/relay-broker/dstack.sock") {
  using client = Deno.createHttpClient({ proxy: { transport: "unix", path: socket } });
  const response = await fetch("http://localhost/GetKey", {
    client, method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "egress-grants-v1", algorithm: "ed25519",
      path: "/tee-daemon/projects/relay-broker/egress-grants-v1", purpose: "dsmack-egress-grants/1" }),
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error("dstack GetKey failed: HTTP " + response.status);
  const { key } = await response.json();
  return signingKey(key);
}
