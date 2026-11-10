// Base Sepolia reads through layover-chain, which answers only what its Helios light client verified. Same interface as
// rpcChain (dstack-compat/secret-release/policy.mjs). The same file is vendored in the layover couch kit as chain.mjs.
import { hex, unhex } from "../../../dstack-compat/secret-release/policy.mjs";

export const CHAIN_READ = "https://pod.dstack.soc1024.com/layover-chain";

// attest: AppleAttestRegistryV1 (keys, cds, validationCategory); canary: Canary; registry: the CDRegistry attest must name.
export function heliosChain({ attest, canary, registry }, base = CHAIN_READ) {
  const call = async (to, data) => {
    const r = await fetch(`${base}/call?to=${to}&data=${data}`), j = await r.json();
    if (!r.ok || j.verified_by !== "helios-opstack") throw new Error(`layover-chain call ${to} ${data.slice(0, 10)}: HTTP ${r.status} ${j.error ?? ""}`);
    return unhex(j.result.slice(2));
  };
  const w = (b, k) => b.subarray(32 * k, 32 * k + 32), int = (b) => BigInt("0x" + hex(b));
  let cds;
  const reg = () => cds ??= call(attest, "0xb4eb10ce").then((b) => {
    const a = "0x" + hex(b.slice(-20));
    if (a !== registry.toLowerCase()) throw new Error(`refused: ${attest} reads CDRegistry ${a}, not ${registry}`);
    return a;
  });
  return {
    key: async (kid) => { const b = await call(attest, "0xdde5b7a1" + hex(kid)); return { x: w(b, 0), y: w(b, 1), expires: Number(int(w(b, 2))), counter: Number(int(w(b, 3))), enrolled: int(w(b, 4)) === 1n }; },
    category: async () => Number(int(await call(attest, "0x5523509a"))),
    rpIdHash: async (cdhash) => call(await reg(), "0x65f4df9c" + hex(cdhash)),
    buildId: async () => call(await reg(), "0xb7b014b6"),
    burnedImage: async (image) => int(await call(canary, "0xe62b7cbd" + hex(image))) === 1n,
    burnedBuild: async (build) => int(await call(canary, "0xda746951" + hex(build))) === 1n,
  };
}
