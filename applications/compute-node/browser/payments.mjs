import {
  AbiCoder,
  keccak256,
  sha256,
  toUtf8Bytes,
} from "./vendor/ethers-6.17.0.mjs";
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
