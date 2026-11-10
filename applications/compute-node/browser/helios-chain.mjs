// Base Sepolia reads through layover-chain, which answers only what its Helios light client verified. snapshot() pins one
// verified block 30 blocks behind the head and returns the rpcChain interface (dstack-compat/secret-release/policy.mjs)
// over it. Helios spends seconds on each new (contract, calldata, block) and queues concurrent ones behind each other,
// so a snapshot fetches each read once, one at a time, and is reused for `maxAge` seconds. A failed read is not kept.
// snapshot() also reads everything verifyNode needs that names no guest, so a caller can do it before opening a stay.
// The same file is vendored in the layover couch kit as chain.mjs.
import { hex, unhex } from "../../../dstack-compat/secret-release/policy.mjs";

export const CHAIN_READ = "https://pod.dstack.soc1024.com/layover-chain";

// attest: AppleAttestRegistryV1 (keys, cds, validationCategory); canary: Canary; registry: the CDRegistry attest must name;
// cdhash and image: the policy's build and OS image.
export function heliosChain({ attest, canary, registry, cdhash, image }, base = CHAIN_READ, maxAge = 30) {
  const get = async (path, what) => {
    const r = await fetch(base + path), j = await r.json();
    if (!r.ok || j.verified_by !== "helios-opstack") throw new Error(`layover-chain ${what}: HTTP ${r.status} ${j.error ?? ""}`);
    return j;
  };
  const pin = async () => {
    const block = (await get("/head?depth=30", "head")).block_hash, reads = new Map();
    const fetchCall = async (to, data) => {
      const j = await get(`/call?to=${to}&data=${data}&block=${block}`, `call ${to} ${data.slice(0, 10)}`);
      if (j.block_hash !== block) throw new Error(`layover-chain answered for block ${j.block_hash}, not ${block}`);
      return unhex(j.result.slice(2));
    };
    const call = (to, data) => {
      const k = to + data;
      if (!reads.has(k)) {
        const p = fetchCall(to, data);
        reads.set(k, p);
        p.catch(() => reads.delete(k));
      }
      return reads.get(k);
    };
    const w = (b, k) => b.subarray(32 * k, 32 * k + 32), int = (b) => BigInt("0x" + hex(b));
    const reg = async () => {
      const a = "0x" + hex((await call(attest, "0xb4eb10ce")).slice(-20));
      if (a !== registry.toLowerCase()) throw new Error(`refused: ${attest} reads CDRegistry ${a}, not ${registry}`);
      return a;
    };
    return {
      key: async (kid) => { const b = await call(attest, "0xdde5b7a1" + hex(kid)); return { x: w(b, 0), y: w(b, 1), expires: Number(int(w(b, 2))), counter: Number(int(w(b, 3))), enrolled: int(w(b, 4)) === 1n }; },
      category: async () => Number(int(await call(attest, "0x5523509a"))),
      rpIdHash: async (cd) => call(await reg(), "0x65f4df9c" + hex(cd)),
      buildId: async () => call(await reg(), "0xb7b014b6"),
      burnedImage: async (img) => int(await call(canary, "0xe62b7cbd" + hex(img))) === 1n,
      burnedBuild: async (build) => int(await call(canary, "0xda746951" + hex(build))) === 1n,
    };
  };
  let last;
  return {
    snapshot: async () => {
      if (!last || Date.now() - last.at > maxAge * 1000) {
        const s = last = { at: Date.now(), chain: pin() };
        s.chain.catch(() => { if (last === s) last = undefined; });
      }
      const chain = await last.chain;
      await chain.category();
      await chain.rpIdHash(unhex(cdhash));
      await chain.burnedImage(unhex(image));
      await chain.burnedBuild(await chain.buildId());
      return chain;
    },
  };
}
