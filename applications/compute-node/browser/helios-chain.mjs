// Base Sepolia reads verified in this page by chain-read's Helios light client (applications/chain-read). snapshot() pins
// Helios's verified head and returns the rpcChain interface (dstack-compat/secret-release/policy.mjs) over it, reused for
// `maxAge` seconds. It also reads everything verifyNode needs that names no guest, in one multicall plus the burned-build
// read, so a caller can do it before opening a stay. Helios loads on the first snapshot and keeps following the head.
import { hex, unhex } from "../../../dstack-compat/secret-release/policy.mjs";

export const CHAIN_READ = "https://chain-read-base-sepolia.socrates1024.workers.dev/chain-read";

// attest: AppleAttestRegistryV1 (keys, cds, validationCategory); canary: Canary; registry: the CDRegistry attest must name;
// cdhash and image: the policy's build and OS image. open() starts the reader; tests pass their own.
export function heliosChain({ attest, canary, registry, cdhash, image }, {
  worker = CHAIN_READ, maxAge = 30,
  open = () => import("../../chain-read/chain-read.mjs").then((m) => m.chainRead({ worker })),
} = {}) {
  let reader, last;
  const start = () => {
    if (!reader) { reader = open(); reader.catch(() => { reader = undefined; }); }
    return reader;
  };
  const pin = async () => {
    const { call, multicall } = await (await start()).snapshot();
    const w = (b, k) => b.subarray(32 * k, 32 * k + 32), int = (b) => BigInt("0x" + hex(b));
    const reg = async () => {
      const a = "0x" + hex((await call(attest, "0xb4eb10ce")).slice(-20));
      if (a !== registry.toLowerCase()) throw new Error(`refused: ${attest} reads CDRegistry ${a}, not ${registry}`);
      return a;
    };
    const chain = {
      key: async (kid) => { const b = await call(attest, "0xdde5b7a1" + hex(kid)); return { x: w(b, 0), y: w(b, 1), expires: Number(int(w(b, 2))), counter: Number(int(w(b, 3))), enrolled: int(w(b, 4)) === 1n }; },
      category: async () => Number(int(await call(attest, "0x5523509a"))),
      rpIdHash: async (cd) => call(await reg(), "0x65f4df9c" + hex(cd)),
      buildId: async () => call(await reg(), "0xb7b014b6"),
      burnedImage: async (img) => int(await call(canary, "0xe62b7cbd" + hex(img))) === 1n,
      burnedBuild: async (build) => int(await call(canary, "0xda746951" + hex(build))) === 1n,
    };
    await multicall([[attest, "0xb4eb10ce"], [attest, "0x5523509a"], [registry, "0x65f4df9c" + hex(unhex(cdhash))],
      [registry, "0xb7b014b6"], [canary, "0xe62b7cbd" + hex(unhex(image))]]);
    await chain.category();
    await chain.rpIdHash(unhex(cdhash));
    await chain.burnedImage(unhex(image));
    await chain.burnedBuild(await chain.buildId());
    return chain;
  };
  return {
    snapshot: async () => {
      if (!last || Date.now() - last.at > maxAge * 1000) {
        const s = last = { at: Date.now(), chain: pin() };
        s.chain.catch(() => { if (last === s) last = undefined; });
      }
      return last.chain;
    },
  };
}
