// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {DemoV1} from "../src/application/DemoV1.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";

/// Apple p2p network: one DemoV1 (admin = deployer) with categories apple-ios and apple-macos,
/// each an AppleAttestRegistryV1 over its own CDRegistry with the approved build registered.
/// Env: PRIVATE_KEY (deployer = admin of DemoV1 and both CDRegistries), MAC_BUILD (cd_args.py JSON of the approved Mac build),
/// DEPLOY_OUT (addresses JSON, under network/).
contract Network is Script {
    bytes16 constant AAGUID = hex"61707061747465737400000000000000";
    function registry(string memory path) internal returns (CDRegistry r) {
        string memory j = vm.readFile(path);
        bytes memory cd = vm.parseJsonBytes(j, ".cd");
        bytes memory page0 = vm.parseJsonBytes(j, ".page0");
        bytes memory ent = vm.parseJsonBytes(j, ".ent");
        r = new CDRegistry();
        r.setBuild(cd, page0, ent, vm.parseJsonUint(j, ".linkeditCmd"), vm.parseJsonUint(j, ".codeSigCmd"));
        r.registerBuild(cd, page0, ent);
    }
    function category(DemoV1 demo, string memory family, CDRegistry cds, uint32 validation, bool ios) internal returns (AppleAttestRegistryV1 a, bytes32 id) {
        a = new AppleAttestRegistryV1(address(demo), cds, AAGUID, validation, ios);
        id = demo.addCategory(bytes32(bytes(family)), keccak256(abi.encode(address(cds))), address(a), true);
        demo.setCategoryEnabled(id, true);
    }
    function run() external returns (DemoV1 demo, AppleAttestRegistryV1 ios, AppleAttestRegistryV1 mac) {
        require(block.chainid == 84532 || block.chainid == 31337, "test network only");
        uint256 key = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(key);
        vm.startBroadcast(key);
        CDRegistry iosCDs = registry("network/cd-args-ios.json");
        CDRegistry macCDs = registry(vm.envString("MAC_BUILD"));
        demo = new DemoV1(deployer);
        bytes32 iosId; bytes32 macId;
        (ios, iosId) = category(demo, "apple-ios", iosCDs, 5, true);
        (mac, macId) = category(demo, "apple-macos", macCDs, 3, false);
        demo.setPaused(false);
        vm.stopBroadcast();
        string memory o = "deploy";
        vm.serializeAddress(o, "admin", deployer);
        vm.serializeAddress(o, "DemoV1", address(demo));
        vm.serializeAddress(o, "DemoTokenV1", address(demo.token()));
        vm.serializeAddress(o, "MembershipReceiptV1", address(demo.receipt()));
        vm.serializeAddress(o, "iosCDRegistry", address(iosCDs));
        vm.serializeAddress(o, "macCDRegistry", address(macCDs));
        vm.serializeAddress(o, "iosAdapter", address(ios));
        vm.serializeAddress(o, "macAdapter", address(mac));
        vm.serializeBytes32(o, "iosCategory", iosId);
        vm.serializeBytes32(o, "macCategory", macId);
        vm.serializeString(o, "DemoV1Artifact", "out/DemoV1.sol/DemoV1.json");
        vm.serializeString(o, "CDRegistryArtifact", "out/CDRegistry.sol/CDRegistry.json");
        string memory out = vm.serializeString(o, "AdapterArtifact", "out/AppleAttestRegistryV1.sol/AppleAttestRegistryV1.json");
        string memory path = vm.envString("DEPLOY_OUT");
        vm.writeJson(out, path);
        console2.log(path);
        console2.log(out);
    }
}
