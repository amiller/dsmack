// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {DstackKmsChain} from "../src/DstackKmsChain.sol";

contract ChainHarness {
    function derivedSigner(address root, address app, string memory purpose, bytes memory d, bytes memory a, bytes memory as_, bytes memory ks) external view returns (address) {
        return DstackKmsChain.derivedSigner(root, app, purpose, d, a, as_, ks);
    }
}

/// The real chain from a live dstack-0.5.8 CVM on Phala's Base KMS (fixtures/dstack/kms-chain-base-20260916.json).
contract DstackKmsChainTest is Test {
    ChainHarness h = new ChainHarness();
    string j;
    function setUp() public { j = vm.readFile("fixtures/dstack/kms-chain-base-20260916.json"); }
    function b(string memory k) internal view returns (bytes memory) { return vm.parseJsonBytes(j, k); }
    function signer(address root, address app, string memory purpose) internal view returns (address) {
        return h.derivedSigner(root, app, purpose, b(".derivedPubkey"), b(".appPubkey"), b(".appSignature"), b(".kmsSignature"));
    }
    function testRealChainRecoversToKmsRoot() public view {
        address root = vm.parseJsonAddress(j, ".kmsRoot");
        address app = vm.parseJsonAddress(j, ".appId");
        assertEq(signer(root, app, "ethereum"), DstackKmsChainHarnessless.toAddress(b(".derivedPubkey")));
    }
    function testRealChainRejectsChanges() public {
        address root = vm.parseJsonAddress(j, ".kmsRoot");
        address app = vm.parseJsonAddress(j, ".appId");
        vm.expectRevert("kms signature"); signer(address(0xBEEF), app, "ethereum");
        vm.expectRevert("kms signature"); signer(root, address(0x2a45), "ethereum");
        vm.expectRevert("app signature"); signer(root, app, "layover-minion");
    }
    /// On a Base mainnet fork: Phala's Base KMS contract publishes the root's pubkey, and it hashes to the pinned address.
    function testKmsRootMatchesBaseKmsContract() public {
        vm.createSelectFork(vm.envString("BASE_RPC"));
        (bool ok, bytes memory out) = vm.parseJsonAddress(j, ".kmsContract").staticcall(abi.encodeWithSignature("kmsInfo()"));
        require(ok, "kmsInfo");
        (bytes memory k256Pubkey,,,) = abi.decode(out, (bytes, bytes, bytes, bytes));
        assertEq(DstackKmsChainHarnessless.toAddress(k256Pubkey), vm.parseJsonAddress(j, ".kmsRoot"));
    }
}

library DstackKmsChainHarnessless {
    function toAddress(bytes memory pubkey) internal view returns (address) { return DstackKmsChain.toAddress(pubkey); }
}
