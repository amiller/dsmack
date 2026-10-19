// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
contract CDRegistryTest is Test {
    string constant D = "fixtures/resign/";
    uint256 constant LINKEDIT = 2320;
    uint256 constant CODESIG = 3608;
    bytes32 constant OURS = 0x90a07dc69293aa64c279caed89cfebd3fde0ad92b510f752ed45ba829157fff6;
    function rd(string memory n, string memory ext) internal view returns (bytes memory) { return vm.readFileBinary(string.concat(D, n, ext)); }
    function registry(bytes memory cd, bytes memory page0, bytes memory ent, uint256 linkedit, uint256 codeSig) internal returns (CDRegistry r) {
        r = new CDRegistry();
        r.setBuild(cd, page0, ent, linkedit, codeSig);
    }
    function mac() internal returns (CDRegistry) { return registry(rd("A-original", ".cd"), rd("A-original", ".page0"), rd("A-original", ".ent"), LINKEDIT, CODESIG); }
    function json(string memory n) internal view returns (bytes memory cd, bytes memory page0, bytes memory ent) {
        string memory j = vm.readFile(string.concat(D, n, ".json"));
        (cd, page0, ent) = (vm.parseJsonBytes(j, ".cd"), vm.parseJsonBytes(j, ".page0"), vm.parseJsonBytes(j, ".ent"));
    }
    function jsonRegistry(string memory n) internal returns (CDRegistry r) {
        string memory j = vm.readFile(string.concat(D, n, ".json"));
        (bytes memory cd, bytes memory page0, bytes memory ent) = json(n);
        r = registry(cd, page0, ent, vm.parseJsonUint(j, ".linkeditCmd"), vm.parseJsonUint(j, ".codeSigCmd"));
    }
    function admit(CDRegistry r, bytes memory cd, bytes memory page0, bytes memory ent) internal returns (bytes32 h) {
        h = r.registerBuild(cd, page0, ent);
        assertEq(h, sha256(cd));
        assertTrue(r.isAdmitted(h));
    }
    function file(CDRegistry r, string memory n) internal returns (bytes32) { return admit(r, rd(n, ".cd"), rd(n, ".page0"), rd(n, ".ent")); }
    /// Real Apple codesign re-signs of the 09-16 probe (data/local-resign-20261005).
    function test_resignFixtures() public {
        CDRegistry r = mac();
        assertEq(OURS, sha256("DC9JH5DRMY.dev.dsmack.provider"));
        // Apple Development re-signs, as a bundle (A) or as a loose file whose CD identifier is the
        // file name (D: with timestamp, G: stripped first, I: plain re-sign). Same code, same entitlements.
        string[4] memory ok = ["A-original", "D-dev-timestamp", "G-strip-then-dev", "I-dev-resign-same"];
        for (uint256 i; i < 4; i++) assertEq(r.rpIdHash(file(r, ok[i])), OURS);
        // No entitlements blob: ad hoc (B, C, H) or signed without entitlements (E). Without the
        // app-attest-opt-in entitlement the build cannot produce a CDHash attestation for this app.
        string[4] memory noEnt = ["B-adhoc", "C-adhoc-otherid", "H-strip-then-adhoc", "E-dev-noent"];
        for (uint256 i; i < 4; i++) { vm.expectRevert("entitlements slot"); r.registerBuild(rd(noEnt[i], ".cd"), rd(noEnt[i], ".page0"), rd(noEnt[i], ".ent")); }
        // Different code.
        vm.expectRevert("page0"); r.registerBuild(rd("M-modified", ".cd"), rd("M-modified", ".page0"), rd("M-modified", ".ent"));
        bytes memory p = rd("A-original", ".page0"); p[100] ^= 0x01;
        vm.expectRevert("page0 hash"); r.registerBuild(rd("A-original", ".cd"), p, rd("A-original", ".ent"));
    }
    function patched(uint256 at, bytes1 x) internal view returns (bytes memory cd) { cd = rd("A-original", ".cd"); cd[at] ^= x; }
    function withEnt(bytes memory ent) internal view returns (bytes memory cd) {
        cd = rd("A-original", ".cd"); bytes32 h = sha256(abi.encodePacked(uint32(0xfade7172), uint32(ent.length + 8), ent));
        for (uint256 i; i < 32; i++) cd[351 - 224 + i] = h[i];
    }
    function test_signerFieldsFreeBehaviorPinned() public {
        CDRegistry r = mac();
        bytes memory page0 = rd("A-original", ".page0");
        bytes memory ent = rd("A-original", ".ent");
        assertEq(r.rpIdHash(admit(r, patched(351 - 1, 0x01), page0, ent)), OURS);    // Info.plist slot
        assertEq(r.rpIdHash(admit(r, patched(351 - 64, 0x01), page0, ent)), OURS);   // requirements slot
        vm.expectRevert("header"); r.registerBuild(patched(0x0d, 0x01), page0, ent);  // flags
        vm.expectRevert("header"); r.registerBuild(patched(0x57, 0x10), page0, ent);  // execSeg flags
        vm.expectRevert("header"); r.registerBuild(patched(0x5b, 0x01), page0, ent);  // runtime
        vm.expectRevert("entitlements slot"); r.registerBuild(rd("A-original", ".cd"), page0, bytes.concat(ent, hex"00"));
        bytes memory e = rd("A-original", ".ent"); e[134] = "X";                       // app-attest-opt-in value
        bytes memory cd = withEnt(e);
        vm.expectRevert("entitlements"); r.registerBuild(cd, page0, e);
        e = rd("A-original", ".ent"); for (uint256 i = 181; i < 191; i++) e[i] = "Z";   // team-identifier value
        assertEq(r.rpIdHash(admit(r, withEnt(e), page0, e)), OURS);
        e = rd("A-original", ".ent"); for (uint256 i = 47; i < 57; i++) e[i] = "Z";     // application-identifier value
        assertEq(r.rpIdHash(admit(r, withEnt(e), page0, e)), sha256("ZZZZZZZZZZ.dev.dsmack.provider"));
    }
    function test_teamMetadataRequiresSealedEntitlements() public {
        CDRegistry r = mac();
        bytes memory page0 = rd("A-original", ".page0");
        bytes memory ent = rd("A-original", ".ent");
        bytes32 original = file(r, "A-original");
        assertEq(r.teamIdHash(original), sha256("DC9JH5DRMY"));
        for (uint256 i = 181; i < 191; i++) ent[i] = "Z";
        vm.expectRevert("entitlements slot");
        r.registerBuild(rd("A-original", ".cd"), page0, ent);
        bytes32 changed = r.registerBuild(withEnt(ent), page0, ent);
        assertTrue(changed != original);
        assertEq(r.teamIdHash(changed), sha256("ZZZZZZZZZZ"));
        assertEq(r.teamIdHash(original), sha256("DC9JH5DRMY"));
        // Registration alone accepts structurally valid metadata, not an Apple
        // signature. Builder awards must require live attestation of changed.
        ent[181] = "!";
        bytes memory malformedCD = withEnt(ent);
        vm.expectRevert("team-identifier");
        r.registerBuild(malformedCD, page0, ent);
        assertEq(r.teamIdHash(bytes32(uint256(123))), 0);
    }
    function test_BundleIdentityIsSealedAndSeparateFromPrefix() public {
        CDRegistry r = mac();bytes32 original = file(r, "A-original");
        assertEq(r.bundleIdHash(original), sha256("dev.dsmack.provider"));
        bytes memory ent = rd("A-original", ".ent");
        for (uint256 i = 47; i < 57; i++) ent[i] = "Z";
        assertEq(r.bundleIdHash(r.registerBuild(withEnt(ent), rd("A-original", ".page0"), ent)), sha256("dev.dsmack.provider"));
        ent[76] = "x";
        bytes32 changed = r.registerBuild(withEnt(ent), rd("A-original", ".page0"), ent);
        assertEq(r.bundleIdHash(changed), sha256("dev.dsmack.providex"));
        assertEq(r.bundleIdHash(original), sha256("dev.dsmack.provider"));
    }
    function test_ownerSetsBuildAndOldBuildsStopResolving() public {
        CDRegistry r = mac();
        bytes32 a = file(r, "A-original");
        (bytes memory cd, bytes memory page0, bytes memory ent) = json("iphone-honest");
        vm.prank(address(1)); vm.expectRevert("owner"); r.setBuild(cd, page0, ent, 2880, 5120);
        r.setBuild(cd, page0, ent, 2880, 5120);
        assertEq(r.rpIdHash(a), 0);
        assertEq(r.teamIdHash(a), 0);
        assertEq(r.bundleIdHash(a), 0);
        assertEq(r.rpIdHash(admit(r, cd, page0, ent)), OURS);
    }
    function test_iphoneBuild() public {
        CDRegistry r = jsonRegistry("iphone-honest");
        (bytes memory cd, bytes memory page0, bytes memory ent) = json("iphone-honest");
        bytes32 h = admit(r, cd, page0, ent);
        assertEq(h, 0x5395bf39ecded47ab804eb78b7f878c246baa4860ca32cad1c63ed468783b591);
        assertEq(r.rpIdHash(h), OURS);
        (cd, page0, ent) = json("iphone-modified");
        vm.expectRevert("code slots"); r.registerBuild(cd, page0, ent);
    }
    /// Synthetic identity metadata on our own node; not Apple-signed second-team evidence.
    function test_syntheticTeamIdentity() public {
        CDRegistry r = jsonRegistry("node-honest");
        (bytes memory cd, bytes memory page0, bytes memory ent) = json("node-honest");
        bytes32 original = admit(r, cd, page0, ent);
        (cd, page0, ent) = json("node-synthetic-team");
        bytes32 changed = admit(r, cd, page0, ent);
        assertTrue(changed != original);
        assertEq(r.rpIdHash(original), OURS);
        assertEq(r.teamIdHash(original), sha256("DC9JH5DRMY"));
        assertEq(r.rpIdHash(changed), sha256("TESTTEAM01.dev.dsmack.provider"));
        assertEq(r.teamIdHash(changed), sha256("TESTTEAM01"));
    }
    function test_missingTeamIsNotInferredFromAppPrefix() public {
        CDRegistry r = jsonRegistry("node-synthetic-prefix-only");
        (bytes memory cd, bytes memory page0, bytes memory ent) = json("node-synthetic-prefix-only");
        bytes32 original = admit(r, cd, page0, ent);
        (cd, page0, ent) = json("node-synthetic-prefix-only-other");
        bytes32 changed = admit(r, cd, page0, ent);
        assertTrue(changed != original);
        assertEq(r.rpIdHash(original), OURS);
        assertEq(r.rpIdHash(changed), sha256("TESTTEAM01.dev.dsmack.provider"));
        assertEq(r.teamIdHash(original), 0);
        assertEq(r.teamIdHash(changed), 0);
        vm.expectRevert("entitlements slot"); r.registerBuild(cd, page0, hex"");
    }
    /// The live-run node builds (data/p2p-run-20261006/builds): B = `codesign --force --signature-size 20000` of A.
    function test_nodeBuilds() public {
        CDRegistry r = jsonRegistry("node-honest");
        (bytes memory cd, bytes memory page0, bytes memory ent) = json("node-honest");
        bytes32 a = admit(r, cd, page0, ent);
        (cd, page0, ent) = json("node-resigned");
        bytes32 b = admit(r, cd, page0, ent);
        assertTrue(a != b);
        assertEq(r.rpIdHash(b), OURS);
        (cd, page0, ent) = json("node-modified");
        vm.expectRevert("code slots"); r.registerBuild(cd, page0, ent);
    }
    function synth(uint256 n) internal view returns (bytes memory cd, bytes memory page0) {
        page0 = new bytes(16384);
        for (uint256 i; i < 16384; i++) page0[i] = bytes1(uint8(i * 7 + 1));
        uint256 off = 0x60 + 20 + 11 + 7 * 32;
        cd = new bytes(off + 32 * n);
        bytes memory h = abi.encodePacked(uint32(0xfade0c02), uint32(cd.length), uint32(0x20500), uint32(0), uint32(off), uint32(0x60), uint32(7), uint32(n), uint32(n * 16384));
        h = bytes.concat(h, new bytes(0x30 - h.length), bytes4(uint32(0x74)), new bytes(0x60 - 0x34), "dev.dsmack.provider\x00DC9JH5DRMY\x00");
        for (uint256 i; i < h.length; i++) cd[i] = h[i];
        cd[0x24] = 0x20; cd[0x25] = 0x02; cd[0x27] = 0x0e;
        bytes memory ea = vm.readFileBinary(string.concat(D, "A-original.ent"));
        bytes32 e = sha256(abi.encodePacked(uint32(0xfade7172), uint32(ea.length + 8), ea));
        for (uint256 i; i < 32; i++) cd[off - 224 + i] = e[i];
        bytes32 s0 = sha256(page0);
        for (uint256 i; i < 32; i++) cd[off + i] = s0[i];
        for (uint256 i = 32; i < 32 * n; i++) cd[off + i] = bytes1(uint8(uint256(keccak256(abi.encode(i / 32))) >> (8 * (i % 32))));
    }
    function measure(uint256 n) internal {
        (bytes memory cd, bytes memory page0) = synth(n);
        bytes memory ent = rd("A-original", ".ent");
        CDRegistry r = registry(cd, page0, ent, LINKEDIT, CODESIG);
        r.registerBuild(cd, page0, ent);
        uint256 exec = vm.lastCallGas().gasTotalUsed;
        bytes memory d = abi.encodeCall(CDRegistry.registerBuild, (cd, page0, ent));
        uint256 z;
        for (uint256 i; i < d.length; i++) if (d[i] == 0) z++;
        uint256 nz = d.length - z;
        uint256 std = 16 * nz + 4 * z;
        uint256 floor = 10 * (4 * nz + z);
        emit log_named_uint("slots", n);
        emit log_named_uint("calldata bytes", d.length);
        emit log_named_uint("exec", exec);
        emit log_named_uint("calldata std", std);
        emit log_named_uint("calldata floor", floor);
        emit log_named_uint("tx total", 21000 + (std + exec > floor ? std + exec : floor));
    }
    function test_gas1280() public { measure(1280); }
    function test_gas3200() public { measure(3200); }
    function test_gas6400() public { measure(6400); }
}
