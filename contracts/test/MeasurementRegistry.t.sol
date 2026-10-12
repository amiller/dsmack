// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {MeasurementRegistry} from "../src/MeasurementRegistry.sol";
import {AppleAttestMeasuredV1} from "../src/AppleAttestMeasuredV1.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";
import {P256Verifier} from "./P256Verifier.sol";

contract MeasurementRegistryTest is Test {
    bytes32 constant OURS = 0x90a07dc69293aa64c279caed89cfebd3fde0ad92b510f752ed45ba829157fff6;
    MeasurementRegistry r;
    function setUp() public { r = new MeasurementRegistry(); }
    function reg(MeasurementRegistry x, string memory path) internal returns (bytes32) {
        string memory j = vm.readFile(path);
        return x.register(vm.parseJsonBytes(j, ".cd"), vm.parseJsonBytes(j, ".page0"), vm.parseJsonBytes(j, ".ent"), vm.parseJsonUint(j, ".linkeditCmd"), vm.parseJsonUint(j, ".codeSigCmd"));
    }
    function node(string memory n) internal returns (bytes32) { return reg(r, string.concat("fixtures/resign/", n, ".json")); }
    function m(string memory key) internal view returns (bytes32) { return vm.parseJsonBytes32(vm.readFile("fixtures/resign/measure-vectors.json"), key); }

    function test_ownerOnly() public {
        vm.startPrank(address(1));
        vm.expectRevert("owner"); r.admit(m(".node"), 1, 2);
        vm.expectRevert("owner"); r.revoke(m(".node"));
        vm.stopPrank();
        vm.expectRevert("window"); r.admit(m(".node"), 2, 2);
    }
    function test_windowEdges() public {
        r.admit(m(".node"), 100, 200);
        assertFalse(r.isAdmitted(m(".node"), 99));
        assertTrue(r.isAdmitted(m(".node"), 100));
        assertTrue(r.isAdmitted(m(".node"), 199));
        assertFalse(r.isAdmitted(m(".node"), 200));
        assertFalse(r.isAdmitted(m(".nodeModified"), 150));
        vm.roll(50);
        bytes32 h = node("node-honest");                       // registering before activation is allowed
        assertEq(r.measurementOf(h), m(".node"));
        assertEq(r.rpIdHash(h), 0);
        vm.roll(100); assertEq(r.rpIdHash(h), OURS);
        vm.roll(199); assertEq(r.teamIdHash(h), sha256("DC9JH5DRMY"));
        assertEq(r.bundleIdHash(h), sha256("dev.dsmack.provider"));
        vm.roll(200);
        assertEq(r.rpIdHash(h), 0); assertEq(r.teamIdHash(h), 0); assertEq(r.bundleIdHash(h), 0);
        vm.expectRevert("measurement not admitted"); node("node-resigned");
    }
    function test_unregisteredAndUnadmitted() public {
        r.admit(m(".node"), 0, 1000);
        assertEq(r.rpIdHash(sha256("nothing")), 0);
        vm.expectRevert("measurement not admitted"); node("node-modified");
        bytes32 h = node("node-honest");
        assertEq(h, sha256(vm.parseJsonBytes(vm.readFile("fixtures/resign/node-honest.json"), ".cd")));
    }
    /// Any signer of the admitted code registers; identity is recorded per CDHash.
    function test_resignedAndOtherTeam() public {
        r.admit(m(".node"), 0, 1000);
        bytes32 a = node("node-honest");
        bytes32 b = node("node-resigned");
        bytes32 c = node("node-synthetic-team");
        assertTrue(a != b && b != c && a != c);
        assertEq(r.rpIdHash(a), OURS); assertEq(r.rpIdHash(b), OURS);
        assertEq(r.rpIdHash(c), sha256("TESTTEAM01.dev.dsmack.provider"));
        assertEq(r.teamIdHash(c), sha256("TESTTEAM01"));
    }
    /// 0.2.0 (node) and 0.2.1 (node-modified) admitted together, then 0.2.0 expires; then revoke.
    function test_overlap() public {
        r.admit(m(".node"), 0, type(uint64).max);
        bytes32 old = node("node-honest");
        vm.roll(500);
        r.admit(m(".nodeModified"), 500, type(uint64).max);
        r.admit(m(".node"), 0, 700);                            // release: old expires after the overlap
        bytes32 fresh = node("node-modified");
        assertEq(r.rpIdHash(old), OURS); assertEq(r.rpIdHash(fresh), OURS);
        vm.roll(699);
        assertEq(r.rpIdHash(old), OURS); assertEq(r.rpIdHash(fresh), OURS);
        vm.roll(700);
        assertEq(r.rpIdHash(old), 0); assertEq(r.rpIdHash(fresh), OURS);
        vm.expectRevert("measurement not admitted"); node("node-resigned");
        r.revoke(m(".nodeModified"));
        assertEq(r.rpIdHash(fresh), 0);
        (uint64 from, uint64 until) = r.windows(m(".nodeModified"));
        assertEq(from, 0); assertEq(until, 0);
    }
    function test_gas() public {
        r.admit(m(".node"), 0, 1000);
        string memory j = vm.readFile("fixtures/resign/node-honest.json");
        (bytes memory cd, bytes memory page0, bytes memory ent) = (vm.parseJsonBytes(j, ".cd"), vm.parseJsonBytes(j, ".page0"), vm.parseJsonBytes(j, ".ent"));
        bytes32 h = r.register(cd, page0, ent, vm.parseJsonUint(j, ".linkeditCmd"), vm.parseJsonUint(j, ".codeSigCmd"));
        emit log_named_uint("register(node) call gas", vm.lastCallGas().gasTotalUsed);
        r.rpIdHash(h);
        emit log_named_uint("rpIdHash call gas", vm.lastCallGas().gasTotalUsed);
        CDRegistry old = new CDRegistry();
        old.setBuild(cd, page0, ent, vm.parseJsonUint(j, ".linkeditCmd"), vm.parseJsonUint(j, ".codeSigCmd"));
        old.registerBuild(cd, page0, ent);
        emit log_named_uint("CDRegistry.registerBuild(node) call gas", vm.lastCallGas().gasTotalUsed);
    }
}

/// Real macOS 27 App Attest enrollment and assertions (fixtures/fresh-apple.json) through the new adapter.
contract AppleAttestMeasuredV1Test is Test {
    function test_enrollAssertExpire() public {
        P256Verifier p = new P256Verifier(); vm.etch(address(0x100), address(p).code);
        vm.warp(1789588800); vm.roll(10);
        string memory f = vm.readFile("fixtures/fresh-apple.json");
        string memory b = vm.readFile("fixtures/cd-args-probe-macos.json");
        bytes memory guid = vm.parseJsonBytes(f, ".aaguid");
        MeasurementRegistry r = new MeasurementRegistry();
        AppleAttestMeasuredV1 a = new AppleAttestMeasuredV1(address(this), r, bytes16(guid), 3, false);
        bytes32 probe = vm.parseJsonBytes32(vm.readFile("fixtures/resign/measure-vectors.json"), ".probe");
        bytes memory cd = vm.parseJsonBytes(b, ".cd");
        vm.expectRevert("measurement not admitted");
        r.register(cd, vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"), vm.parseJsonUint(b, ".linkeditCmd"), vm.parseJsonUint(b, ".codeSigCmd"));
        r.admit(probe, 0, 100);
        assertEq(r.register(cd, vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"), vm.parseJsonUint(b, ".linkeditCmd"), vm.parseJsonUint(b, ".codeSigCmd")), vm.parseJsonBytes32(f, ".cdhash"));
        bytes32 kid = vm.parseJsonBytes32(f, ".kid");
        assertEq(a.enroll(vm.parseJsonBytes(f, ".cert"), vm.parseJsonBytes(f, ".auth"), vm.parseJsonBytes(f, ".clientData")), kid);
        (bytes32 c, bytes memory proof) = assertion(f, kid, "assert");
        assertEq(a.verify(c, proof), kid);
        emit log_named_uint("AppleAttestMeasuredV1.verify call gas", vm.lastCallGas().gasTotalUsed);
        CDRegistry old = new CDRegistry();
        old.setBuild(cd, vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"), vm.parseJsonUint(b, ".linkeditCmd"), vm.parseJsonUint(b, ".codeSigCmd"));
        old.registerBuild(cd, vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"));
        AppleAttestRegistryV1 v1 = new AppleAttestRegistryV1(address(this), old, bytes16(guid), 3, false);
        v1.enroll(vm.parseJsonBytes(f, ".cert"), vm.parseJsonBytes(f, ".auth"), vm.parseJsonBytes(f, ".clientData"));
        v1.verify(c, proof);
        emit log_named_uint("AppleAttestRegistryV1.verify call gas (same assertion)", vm.lastCallGas().gasTotalUsed);
        (c, proof) = assertion(f, kid, "modified");
        vm.expectRevert("build not admitted"); a.verify(c, proof);
        vm.roll(100);
        (c, proof) = assertion(f, kid, "restored");
        vm.expectRevert("build not admitted"); a.verify(c, proof);
        r.admit(probe, 0, 200);
        assertEq(a.verify(c, proof), kid);
    }
    function assertion(string memory f, bytes32 kid, string memory n) internal pure returns (bytes32, bytes memory) {
        return (sha256(vm.parseJsonBytes(f, string.concat(".", n, ".context"))), abi.encode(kid, vm.parseJsonBytes(f, string.concat(".", n, ".auth")),
            uint256(vm.parseJsonBytes32(f, string.concat(".", n, ".r"))), uint256(vm.parseJsonBytes32(f, string.concat(".", n, ".s")))));
    }
}
