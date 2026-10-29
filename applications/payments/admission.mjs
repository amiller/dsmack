import { keccak256, require } from "./schema.mjs";
import { hex, unhex } from "../../dstack-compat/secret-release/policy.mjs";

// Attest, CDRegistry and canary reads share the payment's finalized snapshot.
export async function admissionChain(s, cfg) {
  require(
    cfg.admissionCode?.length === 3,
    "pin Attest, CDRegistry and Canary deployed code",
  );
  for (const pin of cfg.admissionCode) {
    const code = await s.read("eth_getCode", [pin.address, s.tag]);
    require(
      code !== "0x" && keccak256(code) === pin.codeHash,
      "admission contract code mismatch",
    );
  }
  const call = async (to, data) =>
    unhex((await s.read("eth_call", [{ to, data }, s.tag])).slice(2));
  const int = (b) => BigInt("0x" + hex(b)),
    w = (b, k) => b.subarray(k * 32, (k + 1) * 32);
  const registry = "0x" +
    hex((await call(cfg.attest, "0xb4eb10ce")).slice(-20));
  for (const address of [cfg.attest, registry, cfg.canary]) {
    require(
      cfg.admissionCode.some((p) =>
        p.address.toLowerCase() === address.toLowerCase()
      ),
      "admission address is not code-pinned",
    );
  }
  return {
    key: async (kid) => {
      const b = await call(cfg.attest, "0xdde5b7a1" + hex(kid));
      return {
        x: w(b, 0),
        y: w(b, 1),
        expires: Number(int(w(b, 2))),
        counter: Number(int(w(b, 3))),
        enrolled: int(w(b, 4)) === 1n,
      };
    },
    category: async () => Number(int(await call(cfg.attest, "0x5523509a"))),
    rpIdHash: (cd) => call(registry, "0x65f4df9c" + hex(cd)),
    buildId: () => call(registry, "0xb7b014b6"),
    burnedImage: async (image) =>
      int(await call(cfg.canary, "0xe62b7cbd" + hex(image))) !== 0n,
    burnedBuild: async (build) =>
      int(await call(cfg.canary, "0xda746951" + hex(build))) !== 0n,
  };
}
