// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {LastResortBuyer} from "../src/LastResortBuyer.sol";

/// LAYC and its only minter on Base mainnet, in three transactions from one deployer EOA: LayoverCredit with the
/// LastResortBuyer proxy's address (predicted from the deployer's nonce) as owner, the LastResortBuyer implementation, and
/// the ERC1967 proxy, initialized with CONTROLLER (upgrades, minion key) and MINION (signs books and units). Supply is zero.
/// MainnetLaunch then takes the printed LAYC address.
contract IssuanceLaunch is Script {
    function run() external {
        require(block.chainid == 8453, "Base mainnet only");
        (address controller, address minion) = (vm.envAddress("CONTROLLER"), vm.envAddress("MINION"));
        vm.startBroadcast();
        address proxyAt = vm.computeCreateAddress(msg.sender, vm.getNonce(msg.sender) + 2);
        LayoverCredit layc = new LayoverCredit(proxyAt);
        LastResortBuyer impl = new LastResortBuyer(layc);
        LastResortBuyer lrb = LastResortBuyer(address(new ERC1967Proxy(address(impl), abi.encodeCall(LastResortBuyer.initialize, (controller, minion)))));
        vm.stopBroadcast();
        require(address(lrb) == proxyAt && layc.owner() == address(lrb) && layc.totalSupply() == 0, "LAYC owned by the proxy, no supply");
        require(lrb.controller() == controller && lrb.minion() == minion && address(lrb.token()) == address(layc), "LRB state");
        require(address(uint160(uint256(vm.load(address(lrb), 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)))) == address(impl), "impl slot");
        console2.log("LayoverCredit", address(layc));
        console2.log("LastResortBuyer implementation", address(impl));
        console2.log("LastResortBuyer proxy (LAYC owner)", address(lrb));
    }
}
