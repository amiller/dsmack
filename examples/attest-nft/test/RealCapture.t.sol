// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {P256Verifier} from "attest-test/P256Verifier.sol";
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {CDRegistry} from "dsmack/CDRegistry.sol";
import {AppleAttestAnyBuildV1} from "dsmack/AppleAttestRegistryV1.sol";

/// calldata.py's output for a real Mac probe capture (2026-09-16, Apple Development, approved probe build)
/// enrolls and asserts through the real verifier. The intermediate id is replaced with the test's own endorsement.
contract RealCaptureTest is Test {
    function test_calldataEnrollsAndAssertsOnRealVerifier() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        string memory j = vm.readFile("test/fixtures/probe-20260916.json");
        vm.warp(vm.parseJsonUint(j, ".at"));
        AppleEndorsements en = new AppleEndorsements();
        bytes32 id = en.endorseIntermediate(vm.parseJsonBytes(j, ".intermediate"));
        string memory b = vm.readFile("test/fixtures/probe-20260916-build.json");
        (bytes memory cd, bytes memory page0, bytes memory ent) = (vm.parseJsonBytes(b, ".cd"), vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"));
        CDRegistry cds = new CDRegistry();
        cds.setBuild(cd, page0, ent);
        bytes32 cdhash = cds.registerBuild(cd, page0, ent);
        AppleAttestAnyBuildV1 v = new AppleAttestAnyBuildV1(en, address(this), cds, bytes16("appattest"), 3, false);
        (bytes memory cert, bytes memory auth, bytes memory clientData,) = abi.decode(this.slice(vm.parseJsonBytes(j, ".enroll")), (bytes, bytes, bytes, bytes32));
        v.enroll(cert, auth, clientData, id);
        bytes memory claim = vm.parseJsonBytes(j, ".claim");
        (, bytes memory proof) = abi.decode(this.slice(claim), (address, bytes));
        bytes32 kid = v.verify(vm.parseJsonBytes32(j, ".context"), proof);
        (, bytes32 got,,,) = v.assertionEvidence(kid);
        assertEq(got, cdhash);
        assertEq(cds.buildOf(got), cds.buildId());
    }

    function slice(bytes calldata c) external pure returns (bytes memory) { return c[4:]; }
}
