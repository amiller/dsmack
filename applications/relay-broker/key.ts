import { Wallet } from "../payments/schema.mjs";
import { signingKey } from "./grants.mjs";

// The webhost honours the requested GetKey path whichever project's socket asks,
// so the path must name this deployment's project (config signerProject).
// The webhost keys GetKey by the project that owns the socket, not by the requested path. In the shared
// Deno runtime every project's socket dir is visible, so the socket must be this project's own.
export const projectSocket = (project: string) => {
  if (!project) throw new Error("config signerProject is required");
  return `/run/broker/${project}/dstack.sock`;
};
export const keyPath = (project: string, name: string) => {
  if (!/^[a-z0-9-]+$/.test(project ?? "")) throw new Error("config signerProject is required");
  return "/tee-daemon/projects/" + project + "/" + name;
};

export async function getSigningKey(
  socket: string,
  project: string,
  paid = false,
) {
  using client = Deno.createHttpClient({
    proxy: { transport: "unix", path: socket },
  });
  const name = paid ? "payments-grants-v1" : "egress-grants-v1";
  const response = await fetch("http://localhost/GetKey", {
    client,
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name,
      algorithm: paid ? "secp256k1" : "ed25519",
      path: keyPath(project, name),
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
export async function getProviderEnvKey(
  socket: string,
  project: string,
) {
  using client = Deno.createHttpClient({
    proxy: { transport: "unix", path: socket },
  });
  const response = await fetch("http://localhost/GetKey", {
    client,
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name: "inference-env-v1",
      algorithm: "secp256k1",
      path: keyPath(project, "inference-env-v1"),
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
