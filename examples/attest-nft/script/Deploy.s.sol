// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script} from "forge-std/Script.sol";
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {CDRegistry} from "dsmack/CDRegistry.sol";
import {AppleAttestAnyBuildV1} from "dsmack/AppleAttestRegistryV1.sol";
import {IAttestVerifier} from "dsmack/Canary.sol";
import {AttestNFT} from "../AttestNFT.sol";

/// BUILD=<cd_args.py output for the approved app> forge script script/Deploy.s.sol --rpc-url $RPC --account deployer --broadcast
/// Approves that build in a new CDRegistry, registers its own CDHash, and deploys the verifier and the NFT.
contract Deploy is Script {
    AppleEndorsements constant ENDORSEMENTS = AppleEndorsements(0xb3263f9B42F42d0F8cCABB7014b2EE189580dd81);

    function run() external {
        string memory j = vm.readFile(vm.envString("BUILD"));
        (bytes memory cd, bytes memory page0, bytes memory ent) = (vm.parseJsonBytes(j, ".cd"), vm.parseJsonBytes(j, ".page0"), vm.parseJsonBytes(j, ".ent"));
        vm.startBroadcast();
        (, address me,) = vm.readCallers();
        CDRegistry cds = new CDRegistry();
        cds.setBuild(cd, page0, ent);
        cds.registerBuild(cd, page0, ent);
        address nft = vm.computeCreateAddress(me, vm.getNonce(me) + 1);
        AppleAttestAnyBuildV1 attest = new AppleAttestAnyBuildV1(ENDORSEMENTS, nft, cds, bytes16("appattest"), 6, false);
        require(address(new AttestNFT(IAttestVerifier(address(attest)), cds.buildId())) == nft, "nft address");
        vm.stopBroadcast();
        vm.writeJson(vm.serializeAddress("d", "nft", nft), "deployment.json");
        vm.writeJson(vm.serializeAddress("d", "verifier", address(attest)), "deployment.json");
        vm.writeJson(vm.serializeAddress("d", "cds", address(cds)), "deployment.json");
    }
}
