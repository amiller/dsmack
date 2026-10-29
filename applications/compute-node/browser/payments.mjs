import {
  AbiCoder,
  keccak256,
  sha256,
  toUtf8Bytes,
  verifyTypedData,
} from "./vendor/ethers-6.17.0.mjs";
export const Grant = [
  ["purchaseId", "uint256"],
  ["node", "bytes32"],
  ["runId", "bytes32"],
  ["buyerKey", "bytes32"],
  ["unit", "uint8"],
  ["amount", "uint128"],
  ["issuedAt", "uint64"],
  ["serviceUntil", "uint64"],
  ["destinationPolicyHash", "bytes32"],
].map(([name, type]) => ({ name, type }));
export const Receipt = [
  ["purchaseId", "uint256"],
  ["sequence", "uint64"],
  ["used", "uint128"],
  ["endedAt", "uint64"],
  ["finalReceipt", "bool"],
].map(([name, type]) => ({ name, type }));
export const NodeBinding = [
  ["node", "bytes32"],
  ["operator", "address"],
  ["receiptSigner", "address"],
  ["composeHash", "bytes32"],
  ["imageHash", "bytes32"],
  ["runId", "bytes32"],
  ["expires", "uint64"],
].map(([name, type]) => ({ name, type }));
export const domain = (escrow) => ({
  name: "DsmackUsageEscrow",
  version: "2",
  chainId: 84532,
  verifyingContract: escrow,
});
export { verifyTypedData };
export function paymentRunId(enrollmentKeyId, runNonce) {
  return keccak256(
    AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [
      enrollmentKeyId,
      runNonce,
    ]),
  );
}
export function paymentBinding(p, peer, compose, image) {
  return keccak256(
    AbiCoder.defaultAbiCoder().encode([
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
      84532,
      p.escrow,
      p.node,
      p.runId,
      p.operator,
      p.receiptSigner,
      sha256(toUtf8Bytes(peer)),
      "0x" + compose,
      "0x" + image,
      p.buildId,
      p.runExpires,
    ]),
  );
}
