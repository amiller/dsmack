// Build local operational configuration from P1's deployment and finalized code reads.
import { CHAIN, json, keccak256, require, RPCS } from "./schema.mjs";
import { Quorum } from "./quorum.mjs";
const [deploymentPath, grantSigner, destinationPolicyHash, output] = Deno.args;
require(
  output,
  "usage: configure.mjs DEPLOYMENT_JSON GRANT_SIGNER POLICY_HASH OUTPUT_JSON",
);
const deployment = JSON.parse(await Deno.readTextFile(deploymentPath));
require(deployment.chainId === CHAIN, "Base Sepolia deployment required");
const cfg = {
  escrow: deployment.address,
  codeHash: deployment.runtimeKeccak,
  rpcs: RPCS,
  fundingAddress: deployment.fundingWallet,
  grantSigner,
  destinationPolicyHash,
  attest: "0xdd86D0da349104534AbE7155DBc04D33B74C0A53",
  canary: "0xdC66c90291973167126a3c4455D5A6064634f3B1",
};
const q = new Quorum(cfg), s = await q.snapshot();
const registryRaw = await s.read("eth_call", [{
  to: cfg.attest,
  data: "0xb4eb10ce",
}, s.tag]);
const registry = "0x" + registryRaw.slice(-40);
cfg.admissionCode = [];
for (const address of [cfg.attest, registry, cfg.canary]) {
  const code = await s.read("eth_getCode", [address, s.tag]);
  require(code !== "0x", "missing admission contract");
  cfg.admissionCode.push({ address, codeHash: keccak256(code) });
}
require(
  /^0x[0-9a-fA-F]{40}$/.test(grantSigner) &&
    /^0x[0-9a-fA-F]{64}$/.test(destinationPolicyHash),
  "grant signer address and policy hash required",
);
await Deno.writeTextFile(output, json(cfg), { mode: 0o600, createNew: true });
console.log(json({ config: output, finalizedBlock: s.block.hash }));
