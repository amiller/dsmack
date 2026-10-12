// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {AppRegistry} from "../src/AppRegistry.sol";

contract AppRegistryTest is Test {
    event AppCreated(bytes32 indexed appId, bytes32 scope);
    event AdminSet(bytes32 indexed appId, address admin);
    event ComposeAdmitted(bytes32 indexed appId, bytes32 indexed composeHash, uint64 from, uint64 until);
    AppRegistry r;
    address admin = address(0xA11CE);
    bytes32 constant X = keccak256("app-x");
    bytes32 constant Y = keccak256("app-y");
    bytes32 constant C1 = keccak256("compose-1");
    bytes32 constant C2 = keccak256("compose-2");
    function setUp() public { r = new AppRegistry(); }

    function test_ownerCreatesAndNamesAdmin() public {
        vm.expectEmit(true, false, false, true); emit AppCreated(X, bytes32(0));
        vm.expectEmit(true, false, false, true); emit AdminSet(X, admin);
        r.createApp(X, admin, 0);
        (address a, bytes32 s) = r.apps(X);
        assertEq(a, admin); assertEq(s, 0);
        vm.expectRevert("app id"); r.createApp(X, admin, 0);
        vm.expectRevert("app id"); r.createApp(0, admin, 0);
        vm.expectRevert("admin"); r.createApp(Y, address(0), 0);
        vm.prank(admin); vm.expectRevert("owner"); r.createApp(Y, admin, 0);
        vm.prank(admin); vm.expectRevert("owner"); r.setAdmin(X, address(2));
        vm.expectRevert("admin"); r.setAdmin(Y, address(2));
        r.setAdmin(X, address(2));
        (a,) = r.apps(X); assertEq(a, address(2));
        vm.prank(admin); vm.expectRevert("app admin"); r.admit(X, C1, 0, 1);
    }
    function test_adminOnlyWindows() public {
        r.createApp(X, admin, bytes32("coupon"));
        vm.expectRevert("app admin"); r.admit(X, C1, 0, 10);
        vm.expectRevert("app admin"); r.admit(Y, C1, 0, 10);
        vm.prank(address(0)); vm.expectRevert("app admin"); r.admit(Y, C1, 0, 10);
        vm.startPrank(admin);
        vm.expectRevert("window"); r.admit(X, C1, 5, 5);
        vm.expectEmit(true, true, false, true); emit ComposeAdmitted(X, C1, 5, 10);
        r.admit(X, C1, 5, 10);
        vm.stopPrank();
        vm.expectRevert("app admin"); r.revoke(X, C1);
    }
    /// The node's allow check: compose hash C under app id at a given block.
    function test_allowAtBlock() public {
        r.createApp(X, admin, 0);
        r.createApp(Y, admin, 0);
        vm.startPrank(admin);
        r.admit(X, C1, 100, 200);
        r.admit(Y, C2, 0, type(uint64).max);
        assertFalse(r.isAllowed(X, C1, 99));
        assertTrue(r.isAllowed(X, C1, 100));
        assertTrue(r.isAllowed(X, C1, 199));
        assertFalse(r.isAllowed(X, C1, 200));
        assertFalse(r.isAllowed(X, C2, 150));     // C2 is Y's, not X's
        assertFalse(r.isAllowed(Y, C1, 150));
        assertTrue(r.isAllowed(Y, C2, 150));
        assertFalse(r.isAllowed(keccak256("nope"), C1, 150));
        r.admit(X, C2, 150, 300);                 // upgrade overlap, then shorten the old window
        r.admit(X, C1, 100, 160);
        assertTrue(r.isAllowed(X, C1, 159) && r.isAllowed(X, C2, 159));
        assertFalse(r.isAllowed(X, C1, 160));
        vm.expectEmit(true, true, false, true); emit ComposeAdmitted(X, C2, 0, 0);
        r.revoke(X, C2);
        assertFalse(r.isAllowed(X, C2, 200));
        (uint64 f, uint64 u) = r.composes(X, C2); assertEq(f, 0); assertEq(u, 0);
    }
}
