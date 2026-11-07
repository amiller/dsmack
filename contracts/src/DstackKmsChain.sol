// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice A dstack (0.5.x) GetKey signature chain, checked on chain. Ported from teleport tee-interop DstackVerifier.
/// The KMS root key signs keccak256("dstack-kms-issued:" || appId || appPubkey) when it releases an app's key, which it
/// does only for a compose hash the app's on-chain DstackApp contract allows. The app key signs
/// keccak256(purpose || ":" || hex(derivedPubkey)) for each key GetKey derives. Pubkeys are compressed secp256k1;
/// signatures are r || s || recovery id (0 or 1).
library DstackKmsChain {
    uint256 constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// Returns the derived key's address, or reverts unless the chain leads from the KMS `root` to `appId`.
    function derivedSigner(address root, address appId, string memory purpose, bytes memory derivedPubkey,
        bytes memory appPubkey, bytes memory appSignature, bytes memory kmsSignature) internal view returns (address) {
        require(_recover(keccak256(abi.encodePacked("dstack-kms-issued:", appId, appPubkey)), kmsSignature) == root, "kms signature");
        require(_recover(keccak256(abi.encodePacked(purpose, ":", _hex(derivedPubkey))), appSignature) == toAddress(appPubkey), "app signature");
        return toAddress(derivedPubkey);
    }

    function toAddress(bytes memory pubkey) internal view returns (address) {
        require(pubkey.length == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03), "compressed pubkey");
        uint256 x;
        assembly { x := mload(add(pubkey, 33)) }
        require(x < P, "pubkey");
        uint256 y2 = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        uint256 y = _modExp(y2, (P + 1) / 4);
        require(mulmod(y, y, P) == y2, "pubkey not on curve");
        if ((y & 1) != uint8(pubkey[0]) - 2) y = P - y;
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    function _recover(bytes32 digest, bytes memory sig) private pure returns (address) {
        require(sig.length == 65 && uint8(sig[64]) < 2, "signature");
        bytes32 r; bytes32 s;
        assembly { r := mload(add(sig, 32)) s := mload(add(sig, 64)) }
        return ECDSA.recover(digest, uint8(sig[64]) + 27, r, s);
    }
    function _modExp(uint256 b, uint256 e) private view returns (uint256 r) {
        (bool ok, bytes memory out) = address(0x05).staticcall(abi.encode(32, 32, 32, b, e, P));
        require(ok, "modexp");
        r = abi.decode(out, (uint256));
    }
    function _hex(bytes memory data) private pure returns (bytes memory s) {
        bytes16 alphabet = "0123456789abcdef";
        s = new bytes(data.length * 2);
        for (uint256 i; i < data.length; i++) (s[2 * i], s[2 * i + 1]) = (alphabet[uint8(data[i]) >> 4], alphabet[uint8(data[i]) & 15]);
    }
}
