// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Network} from "./Network.s.sol";
import {DemoV2} from "../src/application/DemoV2.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";

/// Separate deployment: never changes the existing V1 demonstration network.
contract ReleaseNetwork is Network {
    function deploy() external {
        require(block.chainid == 84532 || block.chainid == 31337,"test network only");
        uint32 validation=uint32(vm.envOr("MAC_VALIDATION",uint256(6)));
        require(validation==3 || validation==6,"Mac release profile");
        uint256 key=vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(key);
        CDRegistry cds=registry(vm.envString("MAC_BUILD"));
        DemoV2 demo=new DemoV2(vm.addr(key));
        (AppleAttestRegistryV1 adapter,bytes32 id)=category(demo,"apple-macos",cds,validation,false);
        demo.setPaused(false);
        vm.stopBroadcast();
        string memory o="release";
        vm.serializeUint(o,"protocolVersion",2);
        vm.serializeAddress(o,"admin",vm.addr(key));
        vm.serializeAddress(o,"DemoV1",address(demo)); // Existing relay's address field.
        vm.serializeAddress(o,"macCDRegistry",address(cds));
        vm.serializeAddress(o,"macAdapter",address(adapter));
        vm.serializeBytes32(o,"macCategory",id);
        vm.serializeString(o,"DemoV1Artifact","out/DemoV2.sol/DemoV2.json");
        vm.serializeString(o,"CDRegistryArtifact","out/CDRegistry.sol/CDRegistry.json");
        string memory result=vm.serializeString(o,"AdapterArtifact","out/AppleAttestRegistryV1.sol/AppleAttestRegistryV1.json");
        vm.writeJson(result,vm.envString("DEPLOY_OUT"));
    }
}
