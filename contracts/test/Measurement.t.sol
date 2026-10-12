// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {MeasurementRegistry} from "../src/MeasurementRegistry.sol";

/// Shared vectors with tests/test_measure.py and node/tests/MeasureVectors.swift.
contract MeasurementTest is Test {
    string constant D = "fixtures/resign/";
    MeasurementRegistry r = new MeasurementRegistry();
    string v = vm.readFile("fixtures/resign/measure-vectors.json");
    struct In { bytes cd; bytes page0; bytes ent; uint256 L; uint256 S; }
    function load(string memory n) internal view returns (In memory x) {
        if (vm.exists(string.concat(D, n, ".json"))) {
            string memory j = vm.readFile(string.concat(D, n, ".json"));
            return In(vm.parseJsonBytes(j, ".cd"), vm.parseJsonBytes(j, ".page0"), vm.parseJsonBytes(j, ".ent"), vm.parseJsonUint(j, ".linkeditCmd"), vm.parseJsonUint(j, ".codeSigCmd"));
        }
        x = In(vm.readFileBinary(string.concat(D, n, ".cd")), vm.readFileBinary(string.concat(D, n, ".page0")), vm.readFileBinary(string.concat(D, n, ".ent")), vm.parseJsonUint(v, ".L"), vm.parseJsonUint(v, ".S"));
    }
    function m(In memory x) internal view returns (bytes32) { return r.measure(x.cd, x.page0, x.ent, x.L, x.S); }
    function test_vectors() public view {
        string[] memory same = vm.parseJsonStringArray(v, ".probeSame");
        for (uint256 i; i < same.length; i++) assertEq(m(load(same[i])), vm.parseJsonBytes32(v, ".probe"));
        same = vm.parseJsonStringArray(v, ".nodeSame");
        for (uint256 i; i < same.length; i++) assertEq(m(load(same[i])), vm.parseJsonBytes32(v, ".node"));
        assertEq(m(load("M-modified")), vm.parseJsonBytes32(v, ".probeModified"));
        assertEq(m(load("node-modified")), vm.parseJsonBytes32(v, ".nodeModified"));
        assertTrue(vm.parseJsonBytes32(v, ".node") != vm.parseJsonBytes32(v, ".nodeModified"));
        assertTrue(sha256(load("node-honest").cd) != sha256(load("node-resigned").cd));
    }
    function test_rejected() public {
        string[] memory names = vm.parseJsonKeys(v, ".rejected");
        for (uint256 i; i < names.length; i++) {
            In memory x = load(names[i]);
            vm.expectRevert(bytes(vm.parseJsonString(v, string.concat(".rejected.", names[i]))));
            r.measure(x.cd, x.page0, x.ent, x.L, x.S);
        }
    }
    function off(bytes memory cd) internal pure returns (uint256) { return uint32(bytes4(abi.encodePacked(cd[16], cd[17], cd[18], cd[19]))); }
    function flip(uint256 at) internal view returns (bytes32) { In memory x = load("A-original"); x.cd[at] ^= 0x01; return m(x); }
    function sealEnt(In memory x) internal pure {
        bytes32 h = sha256(abi.encodePacked(uint32(0xfade7172), uint32(x.ent.length + 8), x.ent));
        uint256 o = off(x.cd);
        for (uint256 i; i < 32; i++) x.cd[o - 224 + i] = h[i];
    }
    function test_signerFieldsFreeBehaviorPinned() public {
        bytes32 probe = vm.parseJsonBytes32(v, ".probe");
        uint256 o = off(load("A-original").cd);
        uint256[6] memory free = [o - 32, o - 64, o - 96, o - 160, 0x30, 0x14]; // slots -1 -2 -3 -5, teamOffset, identOffset
        for (uint256 i; i < 6; i++) assertEq(flip(free[i]), probe);
        uint256[4] memory pinned = [uint256(0x0d), 0x57, 0x5b, o + 40];          // flags, execSeg flags, runtime, slot 1
        for (uint256 i; i < 4; i++) assertTrue(flip(pinned[i]) != probe);
        In memory x = load("A-original"); x.cd[o - 128] ^= 0x01;
        vm.expectRevert("slots -4/-6"); r.measure(x.cd, x.page0, x.ent, x.L, x.S);
        x = load("A-original"); x.page0[100] ^= 0x01;
        vm.expectRevert("page0 hash"); r.measure(x.cd, x.page0, x.ent, x.L, x.S);
        x = load("A-original");
        vm.expectRevert("load commands"); r.measure(x.cd, x.page0, x.ent, x.L + 8, x.S);
        uint256[3] memory at = [uint256(47), 181, 134];                           // app id, team id, app-attest-opt-in value
        for (uint256 i; i < 3; i++) {
            x = load("A-original"); x.ent[at[i]] ^= 0x01; sealEnt(x);
            assertEq(m(x) == probe, i < 2);
        }
        x = load("A-original"); x.page0[x.L + 32] ^= 0x01;                        // masked __LINKEDIT vmsize
        bytes32 h = sha256(x.page0); for (uint256 i; i < 32; i++) x.cd[o + i] = h[i];
        assertEq(m(x), probe);
    }
    /// DER edge cases (fixtures/resign/measure-der-vectors.json), byte-for-byte with measure.py and Measure.swift.
    function test_derVectors() public {
        string memory j = vm.readFile(string.concat(D, "measure-der-vectors.json"));
        string[] memory names = vm.parseJsonKeys(j, ".accept");
        for (uint256 i; i < names.length; i++) {
            In memory x = load("node-honest"); x.ent = vm.parseJsonBytes(j, string.concat(".accept.", names[i], ".ent")); sealEnt(x);
            assertEq(m(x), vm.parseJsonBytes32(j, string.concat(".accept.", names[i], ".M")), names[i]);
        }
        names = vm.parseJsonKeys(j, ".reject");
        for (uint256 i; i < names.length; i++) {
            In memory x = load("node-honest"); x.ent = vm.parseJsonBytes(j, string.concat(".reject.", names[i], ".ent")); sealEnt(x);
            vm.expectRevert(bytes(vm.parseJsonString(j, string.concat(".reject.", names[i], ".reason"))));
            r.measure(x.cd, x.page0, x.ent, x.L, x.S);
        }
        assertEq(vm.parseJsonBytes32(j, ".accept.otherTeamValues.M"), vm.parseJsonBytes32(v, ".node"));
    }
}
