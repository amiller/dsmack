// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {AppRegistry} from "../src/AppRegistry.sol";

/// Deploys the dsmack-sdk AppRegistry (owner = deployer). Env: PRIVATE_KEY. Optional APP_ID with
/// APP_ADMIN and APP_SCOPE creates one app; COMPOSE_HASH then also opens its window from now on
/// (requires APP_ADMIN = deployer).
contract DeployAppRegistry is Script {
    function run() external returns (AppRegistry r) {
        require(block.chainid == 84532 || block.chainid == 31337, "test network only");
        uint256 key = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(key);
        r = new AppRegistry();
        bytes32 app = vm.envOr("APP_ID", bytes32(0));
        if (app != 0) {
            r.createApp(app, vm.envAddress("APP_ADMIN"), vm.envOr("APP_SCOPE", bytes32(0)));
            bytes32 compose = vm.envOr("COMPOSE_HASH", bytes32(0));
            if (compose != 0) r.admit(app, compose, uint64(block.number), type(uint64).max);
        }
        vm.stopBroadcast();
        console2.log("AppRegistry", address(r));
    }
}
