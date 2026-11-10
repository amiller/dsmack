import { Wallet } from "../payments/schema.mjs";
import { signingKey } from "./grants.mjs";

// The webhost serves one GetKey proxy per project and derives the key path from
// the socket's project, not the request. A default socket here once gave
// relay-broker-staging production's keys, so the deploy manifest must name it.
const projectSocket = (socket?: string) => {
  if (!socket) throw new Error("DSTACK_SOCKET is not set; the deploy manifest must name this project's socket");
  return socket;
};

export async function getSigningKey(socket: string | undefined, paid = false) {
  using client = Deno.createHttpClient({
    proxy: { transport: "unix", path: projectSocket(socket) },
  });
  const name = paid ? "payments-grants-v1" : "egress-grants-v1";
  const response = await fetch("http://localhost/GetKey", {
    client,
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name,
      algorithm: paid ? "secp256k1" : "ed25519",
      path: "/tee-daemon/projects/relay-broker/" + name,
      purpose: paid ? "dsmack-payments-grants/1" : "dsmack-egress-grants/1",
    }),
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) {
    throw new Error("dstack GetKey failed: HTTP " + response.status);
  }
  const { key } = await response.json();
  return paid ? new Wallet("0x" + key.replace(/^0x/, "")) : signingKey(key);
}

// A distinct project-scoped key decrypts provider env; signing identities retain
// their existing derivation names and paths across this addition.
export async function getProviderEnvKey(socket: string | undefined) {
  using client = Deno.createHttpClient({
    proxy: { transport: "unix", path: projectSocket(socket) },
  });
  const response = await fetch("http://localhost/GetKey", {
    client,
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name: "inference-env-v1",
      algorithm: "secp256k1",
      path: "/tee-daemon/projects/relay-broker/inference-env-v1",
      purpose: "dsmack-near-env/1",
    }),
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error("provider environment key unavailable");
  try {
    const { key } = await response.json();
    return new Wallet("0x" + key.replace(/^0x/, ""));
  } catch {
    throw new Error("provider environment key unavailable");
  }
}
