// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {Badge} from "../src/Badge.sol";
import {ICDRegistry} from "../src/Canary.sol";
import {MockAttest} from "./Canary.t.sol";

contract BadgeTest is Test {
    Badge b;
    address alice = address(0xA11CE);
    address mallory = address(0xBAD);
    bytes32 constant RUNNER = keccak256("runner cdhash");
    bytes32 constant RESIGNED = keccak256("runner re-signed by another team");
    bytes32 constant PROBE = keccak256("probe cdhash");
    bytes32 constant BUILD = keccak256("runner build");

    function setUp() public {
        MockAttest m = new MockAttest(ICDRegistry(address(0)));
        m.admit(RUNNER, BUILD);
        m.admit(RESIGNED, BUILD);
        m.admit(PROBE, keccak256("probe build"));
        b = new Badge(m, BUILD);
    }

    function attested(bytes memory rd) internal pure returns (Badge.Attested memory) {
        return Badge.Attested(keccak256("any image"), keccak256("any compose"), keccak256("run"), keccak256("head"), sha256("svc"), rd);
    }

    function proof(Badge.Attested memory a, bytes32 cdhash) internal pure returns (bytes memory) {
        return abi.encode(sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", a.image, a.manifest, a.run, a.head, a.caller, a.reportData)), cdhash);
    }

    function test_relayedClaimMintsToAttestedAddress() public {
        Badge.Attested memory a = attested(b.reportData(alice));
        vm.prank(mallory);
        uint256 id = b.claim(alice, a, proof(a, RESIGNED));
        assertEq(b.ownerOf(id), alice);
        assertEq(b.balanceOf(alice), 1);
    }

    function test_relayerCannotRedirect() public {
        Badge.Attested memory a = attested(b.reportData(alice));
        bytes memory pf = proof(a, RUNNER);
        vm.expectRevert("report_data");
        b.claim(mallory, a, pf);
    }

    function test_oneBadgePerKey() public {
        Badge.Attested memory a = attested(b.reportData(alice));
        b.claim(alice, a, proof(a, RUNNER));
        a = attested(b.reportData(mallory));
        bytes memory pf = proof(a, RUNNER);
        vm.expectRevert("claimed");
        b.claim(mallory, a, pf);
    }

    /// The probe asserts any file it is given, so it could forge the guest Attest context.
    function test_otherBuildRefused() public {
        Badge.Attested memory a = attested(b.reportData(alice));
        bytes memory pf = proof(a, PROBE);
        vm.expectRevert("build");
        b.claim(alice, a, pf);
    }

    function test_transferReverts() public {
        Badge.Attested memory a = attested(b.reportData(alice));
        uint256 id = b.claim(alice, a, proof(a, RUNNER));
        vm.prank(alice);
        vm.expectRevert("non-transferable");
        b.transferFrom(alice, mallory, id);
    }
}
