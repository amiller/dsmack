import {
  AbiCoder,
  getAddress,
  Interface,
  keccak256,
  TypedDataEncoder,
  verifyTypedData,
} from "npm:ethers@6.17.0";
export {
  Contract,
  computeAddress,
  FetchRequest,
  formatEther,
  formatUnits,
  getAddress,
  JsonRpcProvider,
  keccak256,
  parseEther,
  TypedDataEncoder,
  verifyMessage,
  verifyTypedData,
  Wallet,
} from "npm:ethers@6.17.0";
export const CHAIN = 84532;
export const RPCS = [
  "https://sepolia.base.org",
  "https://base-sepolia-rpc.publicnode.com",
  "https://base-sepolia.drpc.org",
  "https://base-sepolia.gateway.tenderly.co",
];
export const Receipt = [
  { name: "purchaseId", type: "uint256" },
  { name: "sequence", type: "uint64" },
  { name: "unit", type: "uint8" },
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
export const Claim = [
  { name: "operator", type: "address" },
  { name: "cumulativeOwed", type: "uint256" },
  { name: "period", type: "uint64" },
];
export const claimDomain = (escrow, user, chainId = CHAIN) => ({
  name: "DsmackPrepaid", version: "1", chainId, verifyingContract: getAddress(escrow),
  salt: "0x" + user.slice(2).toLowerCase().padStart(64, "0"),
});
export const receiptDomain = (escrow) => ({ ...domain(escrow), name: "dsmack.receipt", version: "5" });
export const abi = new Interface([
  "function owner() view returns (address)",
  "function brokerSigner() view returns (address)",
  "function token() view returns (address)",
  "function registerBroker(address)",
  "function registerNode(bytes32,address,uint8,bytes32,bytes32)",
  "function getNode(bytes32) view returns (tuple(address operator,uint8 unit,bytes32 composeHash,bytes32 imageHash))",
  "function deposits(address) view returns (uint256)",
  "function paid(address) view returns (uint256)",
  "function withdrawn(address) view returns (uint256)",
  "function balance(address) view returns (uint256)",
  "function exitRequestedAt(address) view returns (uint64)",
  "function deposit(uint256)",
  "function requestExit()",
  "function withdraw()",
  "function claim(address,tuple(address operator,uint256 cumulativeOwed,uint64 period),bytes)",
  "function claimed(address,address) view returns (uint256)",
  "event Deposited(address indexed user,uint256 amount)",
  "event Claimed(address indexed user,address indexed operator,uint256 cumulativeOwed,uint64 period)",
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
        "endedAt,finalReceipt,purchaseId,sequence,unit,used",
    "receipt fields",
  );
  require(
    /^[1-9][0-9]*$/.test(r.purchaseId) && /^(0|[1-9][0-9]*)$/.test(r.used) &&
      Number.isSafeInteger(r.sequence) && r.sequence > 0 &&
      Number.isSafeInteger(r.endedAt) && r.endedAt > 0 &&
      [0, 1].includes(r.unit) && typeof r.finalReceipt === "boolean",
    "receipt encoding",
  );
  return verifyTypedData(receiptDomain(escrow), { Receipt }, r, envelope.signature);
}
export const grantSigner = (escrow, g) =>
  verifyTypedData(domain(escrow), { Grant }, g.grant, g.signature);
