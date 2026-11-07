// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {DstackKmsChain} from "../src/DstackKmsChain.sol";
import {LastResortBuyer} from "../src/LastResortBuyer.sol";

interface IBaseKms {
    function kmsInfo() external view returns (bytes memory, bytes memory, bytes memory, bytes memory);
}

/// LAYC and its only minter on Base mainnet, in three transactions from one deployer EOA: LayoverCredit with the
/// LastResortBuyer proxy's address (predicted from the deployer's nonce) as owner, the LastResortBuyer implementation, and
/// the ERC1967 proxy, initialized with CONTROLLER (approves minion builds, revokes minion keys, upgrades). Supply is zero,
/// and no app is approved and no minion registered, so nothing mints until a minion registers. KMS_ROOT is the dstack KMS
/// root signer minion key chains must lead to: on Base mainnet, Phala's Base KMS (kmsInfo().k256Pubkey of
/// 0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C) is 0x52d3CF51c8A37A2CCfC79bBb98c7810d7Dd4CE51. MainnetLaunch then takes the
/// printed LAYC address.
contract IssuanceLaunch is Script {
    function run() external {
        require(block.chainid == 8453, "Base mainnet only");
        (address controller, address kmsRoot) = (vm.envAddress("CONTROLLER"), vm.envAddress("KMS_ROOT"));
        checkKmsRoot(kmsRoot);
        vm.startBroadcast();
        address proxyAt = vm.computeCreateAddress(msg.sender, vm.getNonce(msg.sender) + 2);
        LayoverCredit layc = new LayoverCredit(proxyAt);
        LastResortBuyer impl = new LastResortBuyer(layc, kmsRoot);
        LastResortBuyer lrb = LastResortBuyer(address(new ERC1967Proxy(address(impl), abi.encodeCall(LastResortBuyer.initialize, (controller)))));
        vm.stopBroadcast();
        require(address(lrb) == proxyAt && layc.owner() == address(lrb) && layc.totalSupply() == 0, "LAYC owned by the proxy, no supply");
        require(lrb.controller() == controller && lrb.kmsRoot() == kmsRoot && address(lrb.token()) == address(layc), "LRB state");
        require(address(uint160(uint256(vm.load(address(lrb), 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)))) == address(impl), "impl slot");
        console2.log("LayoverCredit", address(layc));
        console2.log("LastResortBuyer implementation", address(impl));
        console2.log("LastResortBuyer proxy (LAYC owner)", address(lrb));
    }

    function checkKmsRoot(address kmsRoot) internal {
        uint256 uncheckedRoot = vm.envOr("KMS_ROOT_UNCHECKED", uint256(0));
        console2.log("KMS_ROOT_UNCHECKED", uncheckedRoot);
        if (uncheckedRoot != 1) {
            (bytes memory k256Pubkey,,,) = IBaseKms(0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C).kmsInfo();
            require(DstackKmsChain.toAddress(k256Pubkey) == kmsRoot, "kms root");
        }
    }
}
