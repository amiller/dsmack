import {
  AbiCoder,
  getAddress,
  Interface,
  keccak256,
  sha256,
  toUtf8Bytes,
  TypedDataEncoder,
  verifyTypedData,
} from "npm:ethers@6.17.0";
export {
  Contract,
  formatEther,
  getAddress,
  JsonRpcProvider,
  keccak256,
  parseEther,
  TypedDataEncoder,
  Wallet,
} from "npm:ethers@6.17.0";
export const CHAIN = 84532;
export const RPCS = [
  "https://sepolia.base.org",
  "https://base-sepolia-rpc.publicnode.com",
  "https://base-sepolia.drpc.org",
];
export const Receipt = [
  { name: "purchaseId", type: "uint256" },
  { name: "sequence", type: "uint64" },
  { name: "used", type: "uint128" },
  { name: "endedAt", type: "uint64" },
  { name: "finalReceipt", type: "bool" },
];
export const Grant = [
  { name: "purchaseId", type: "uint256" },
  { name: "node", type: "bytes32" },
  { name: "runId", type: "bytes32" },
  { name: "buyerKey", type: "bytes32" },
  { name: "unit", type: "uint8" },
  { name: "amount", type: "uint128" },
  { name: "issuedAt", type: "uint64" },
  { name: "serviceUntil", type: "uint64" },
  { name: "destinationPolicyHash", type: "bytes32" },
];
export const domain = (escrow) => ({
  name: "DsmackUsageEscrow",
  version: "2",
  chainId: CHAIN,
  verifyingContract: getAddress(escrow),
});
export const abi = new Interface([
  "function brokerSigner() view returns (address)",
  "function registerBroker(address)",
  "function registerNode(bytes32,address,uint8,uint128,uint128,bytes32,bytes32)",
  "function checkpoint(bytes32)",
  "function quote(bytes32) view returns (uint128)",
  "function getNode(bytes32) view returns (tuple(address operator,uint8 unit,uint128 floorPrice,uint128 target,uint128 price,uint128 booked,uint64 epoch,bytes32 composeHash,bytes32 imageHash))",
  "function getPurchase(uint256) view returns (tuple(bytes32 node,address payer,bytes32 buyerKey,address operator,uint8 unit,uint128 amount,uint128 price,uint128 floorPrice,uint64 boughtAt,uint64 expires,uint64 sequence,uint128 used,uint64 endedAt,bool closed,bytes32 bindingHash))",
  "function buy(bytes32,uint8,uint128,bytes32) payable returns (uint256)",
  "function settle(tuple(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)[],bytes[],tuple(bytes32 node,address operator,address receiptSigner,bytes32 composeHash,bytes32 imageHash,bytes32 runId,uint64 expires),bytes)",
  "function refund(uint256)",
  "function withdraw()",
  "function credits(address) view returns (uint256)",
  "function lockedPremium() view returns (uint256)",
  "function receiptDigest(tuple(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)) view returns (bytes32)",
  "event Purchase(uint256 indexed purchaseId,bytes32 indexed node,address indexed payer,bytes32 buyerKey,uint8 unit,uint128 amount,uint128 price,uint64 expires)",
  "event Settled(uint256 indexed purchaseId,uint64 sequence,uint128 used,uint256 operatorCredit,uint256 premium,bool finalReceipt)",
  "event Refunded(uint256 indexed purchaseId,address indexed payer,uint256 amount)",
]);
const coder = AbiCoder.defaultAbiCoder();
export const runNode = (enrollmentKeyId, runNonce) =>
  keccak256(coder.encode(["bytes32", "bytes32"], [enrollmentKeyId, runNonce]));
export const NodeBinding = [
  { name: "node", type: "bytes32" },
  { name: "operator", type: "address" },
  { name: "receiptSigner", type: "address" },
  { name: "composeHash", type: "bytes32" },
  { name: "imageHash", type: "bytes32" },
  { name: "runId", type: "bytes32" },
  { name: "expires", type: "uint64" },
];
export const nodeBindingSigner = (escrow, envelope) =>
  verifyTypedData(
    domain(escrow),
    { NodeBinding },
    envelope.binding,
    envelope.signature,
  );
export const nodeBindingHash = (escrow, value) =>
  TypedDataEncoder.hash(domain(escrow), { NodeBinding }, value);
export function binding(p, peer, compose, image) {
  return keccak256(
    coder.encode([
      "bytes32",
      "uint256",
      "address",
      "bytes32",
      "bytes32",
      "address",
      "address",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint64",
    ], [
      keccak256(toUtf8Bytes("DsmackPaymentsNodeV2")),
      CHAIN,
      p.escrow,
      p.node,
      p.runId,
      p.operator,
      p.receiptSigner,
      sha256(toUtf8Bytes(peer)),
      "0x" + compose.replace(/^0x/, ""),
      "0x" + image.replace(/^0x/, ""),
      p.buildId,
      p.runExpires,
    ]),
  );
}
export const json = (v) =>
  JSON.stringify(v, (_, v) => typeof v === "bigint" ? v.toString() : v);
export const require = (ok, message) => {
  if (!ok) throw new Error("refused: " + message);
};
export function receiptSigner(escrow, envelope) {
  const r = envelope.receipt;
  require(
    r &&
      Object.keys(r).sort().join() ===
        "endedAt,finalReceipt,purchaseId,sequence,used",
    "receipt fields",
  );
  require(
    /^[1-9][0-9]*$/.test(r.purchaseId) && /^(0|[1-9][0-9]*)$/.test(r.used) &&
      Number.isSafeInteger(r.sequence) && r.sequence > 0 &&
      Number.isSafeInteger(r.endedAt) && r.endedAt > 0 &&
      typeof r.finalReceipt === "boolean",
    "receipt encoding",
  );
  return verifyTypedData(domain(escrow), { Receipt }, r, envelope.signature);
}
export const grantSigner = (escrow, g) =>
  verifyTypedData(domain(escrow), { Grant }, g.grant, g.signature);
