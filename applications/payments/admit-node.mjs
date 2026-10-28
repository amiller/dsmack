// Admit a challenge-bound node using the Base Sepolia funding wallet.
import {
  binding,
  CHAIN,
  Contract,
  JsonRpcProvider,
  require,
  runNode,
  Wallet,
} from "./schema.mjs";
import { Quorum } from "./quorum.mjs";
import { admissionChain } from "./admission.mjs";
import { verifyRelay, withEnrollment } from "../relay-broker/attestation.mjs";
let owner;
try {
  owner = new Wallet((await Deno.readTextFile(Deno.args[0])).trim());
} catch {
  throw new Error("cannot load a valid raw owner key");
}
require(
  owner.address.toLowerCase() === "0x1fbe7a7b3f7a37a967f3d927abd6f04db2766c5b",
  "owner must be the sprint funding wallet",
);
const cfg = JSON.parse(
  await Deno.readTextFile(
    Deno.env.get("PAYMENTS_CONFIG") ?? "local-data/payments-config.json",
  ),
);
const broker = JSON.parse(
  await Deno.readTextFile(
    Deno.env.get("BROKER_CONFIG") ?? "local-data/broker-config.json",
  ),
);
const node = JSON.parse(
  await Deno.readTextFile(
    Deno.env.get("PAYMENTS_NODE") ?? "local-data/payment-node.json",
  ),
);
const challenge = JSON.parse(
  await Deno.readTextFile(
    Deno.env.get("PAYMENTS_CHALLENGE") ?? "local-data/payment-challenge.json",
  ),
);
const now = Math.floor(Date.now() / 1000);
require(
  challenge.challenge === node.payments.challenge &&
    challenge.createdAt <= now && now - challenge.createdAt < 60,
  "fresh owner challenge required",
);
const s = await new Quorum(cfg).snapshot();
const balance = BigInt(await s.read("eth_getBalance", [owner.address, s.tag]));
require(balance >= 5000000000000000n, "funding wallet below 0.005 ETH reserve");
const checked = await verifyRelay(
  node,
  broker,
  withEnrollment(await admissionChain(s, cfg), broker.enrollments),
  now,
);
const p = node.payments;
require(
  p.escrow.toLowerCase() === cfg.escrow.toLowerCase() &&
    p.grantSigner.toLowerCase() === cfg.grantSigner.toLowerCase(),
  "payment escrow/grant key",
);
require(
  p.enrollmentKeyId.slice(2) === checked.key_id &&
    p.buildId.slice(2) === checked.build_id &&
    runNode(p.enrollmentKeyId, p.runNonce) === p.node,
  "attested enrollment/build/run",
);
const provider = new JsonRpcProvider(cfg.rpcs[0], CHAIN, { batchMaxCount: 1 });
require(
  Number((await provider.getNetwork()).chainId) === CHAIN,
  "Base Sepolia only",
);
const contract = new Contract(cfg.escrow, [
  "function owner() view returns(address)",
  "function registerNode(bytes32,address,address,bytes32,uint8,uint128,uint128,uint64)",
], owner.connect(provider));
const chainOwner = await s.read("eth_call", [{
  to: cfg.escrow,
  data: contract.interface.encodeFunctionData("owner"),
}, s.tag]);
require(
  contract.interface.decodeFunctionResult("owner", chainOwner)[0]
    .toLowerCase() === owner.address.toLowerCase(),
  "escrow owner mismatch",
);
const unit = node.kind === "compute" ? 1 : 0;
const tx = await contract.registerNode(
  p.node,
  p.operator,
  p.receiptSigner,
  binding(p, node.relay_peer, node.manifest_sha256, node.os_image_hash),
  unit,
  unit === 1 ? "10000000000" : "1000",
  unit === 1 ? "30" : "314572800",
  p.runExpires,
);
await tx.wait();
console.log(
  JSON.stringify({ chainId: CHAIN, node: p.node, registration: tx.hash }),
);
