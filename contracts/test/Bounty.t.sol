// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {Bounty} from "../src/Bounty.sol";
import {ICDRegistry} from "../src/Canary.sol";
import {MockAttest} from "./Canary.t.sol";

contract BountyTest is Test {
    Bounty b;
    MockAttest m;
    address payable alice = payable(address(0xA11CE));
    address payable mallory = payable(address(0xBAD));
    bytes32 constant IMAGE = keccak256("guest image");
    bytes32 constant MANIFEST = keccak256("checker compose");
    bytes32 constant CALLER = sha256("checker");
    bytes32 constant RUNNER = keccak256("runner cdhash");
    bytes32 constant RESIGNED = keccak256("runner re-signed by another team");
    bytes32 constant PROBE = keccak256("probe cdhash");
    bytes32 constant BUILD = keccak256("runner build");
    bytes20 constant FIX = bytes20(keccak256("fix commit"));

    function setUp() public {
        m = new MockAttest(ICDRegistry(address(0)));
        m.admit(RUNNER, BUILD);
        m.admit(RESIGNED, BUILD);
        m.admit(PROBE, keccak256("probe build"));
        b = new Bounty(m);
        b.post{value: 1 ether}(BUILD, IMAGE, MANIFEST, CALLER, uint64(block.timestamp + 30 days));
    }

    function attested(bytes32 manifest, bytes32 caller, bytes memory rd) internal pure returns (Bounty.Attested memory) {
        return Bounty.Attested(IMAGE, manifest, keccak256("run"), keccak256("head"), caller, rd);
    }

    function proof(Bounty.Attested memory a, bytes32 cdhash) internal pure returns (bytes memory) {
        return abi.encode(sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", a.image, a.manifest, a.run, a.head, a.caller, a.reportData)), cdhash);
    }

    function fails(address payable payee, bytes20 commit, Bounty.Attested memory a, bytes32 cdhash, bytes memory err) internal {
        bytes memory pf = proof(a, cdhash);
        vm.expectRevert(err);
        b.claim(0, payee, commit, a, pf);
    }

    function test_paysAttestedPayeeOnceFromResignedCopy() public {
        Bounty.Attested memory a = attested(MANIFEST, CALLER, b.reportData(0, alice, FIX));
        vm.prank(mallory);
        b.claim(0, alice, FIX, a, proof(a, RESIGNED));
        assertEq(alice.balance, 1 ether);
        fails(alice, FIX, a, RESIGNED, "paid");
    }

    function test_relayerCannotRedirectPayee() public {
        Bounty.Attested memory a = attested(MANIFEST, CALLER, b.reportData(0, alice, FIX));
        fails(mallory, FIX, a, RUNNER, "report_data");
        fails(alice, bytes20(keccak256("other commit")), a, RUNNER, "report_data");
    }

    function test_refusesOtherWorkloadOrBuild() public {
        bytes memory rd = b.reportData(0, alice, FIX);
        fails(alice, FIX, attested(keccak256("other compose"), CALLER, rd), RUNNER, "not this checker");
        fails(alice, FIX, attested(MANIFEST, sha256("other service"), rd), RUNNER, "not this checker");
        fails(alice, FIX, attested(MANIFEST, CALLER, rd), PROBE, "build");
    }

    function test_funderReclaimsOnlyAfterUntil() public {
        vm.expectRevert(bytes("reclaim"));
        b.reclaim(0);
        vm.warp(block.timestamp + 31 days);
        uint256 before = address(this).balance;
        b.reclaim(0);
        assertEq(address(this).balance, before + 1 ether);
    }

    receive() external payable {}
}
