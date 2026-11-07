// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {Owned} from "../src/Owned.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {GuestEscrow, IGuestAttest} from "../src/GuestEscrow.sol";
import {UsageEscrow} from "../src/UsageEscrow.sol";
import {MockGuestAttest} from "./GuestEscrow.t.sol";

/// Two-step ownership on every contract with an owner role; each owner-gated call follows the transfer.
contract OwnedTest is Test {
    address next = address(0xA11CE);

    function transfer(Owned o) internal {
        vm.prank(next); vm.expectRevert("owner only"); o.transferOwnership(next);
        o.transferOwnership(next);
        assertEq(o.pendingOwner(), next);
        assertEq(o.owner(), address(this));
        vm.prank(address(0xBAD)); vm.expectRevert("pending owner only"); o.acceptOwnership();
        vm.prank(next); o.acceptOwnership();
        assertEq(o.owner(), next);
        assertEq(o.pendingOwner(), address(0));
    }
    function test_cancel() public {
        CDRegistry r = new CDRegistry(address(this));
        r.transferOwnership(next);
        r.transferOwnership(address(0));
        vm.prank(next); vm.expectRevert("pending owner only"); r.acceptOwnership();
        assertEq(r.owner(), address(this));
    }
    function test_cdRegistry() public {
        CDRegistry r = new CDRegistry(address(this));
        transfer(r);
        bytes memory cd = vm.readFileBinary("fixtures/resign/A-original.cd");
        bytes memory page0 = vm.readFileBinary("fixtures/resign/A-original.page0");
        bytes memory ent = vm.readFileBinary("fixtures/resign/A-original.ent");
        vm.expectRevert("owner"); r.setBuild(cd, page0, ent);
        vm.prank(next); r.setBuild(cd, page0, ent);
    }
    function test_guestEscrow() public {
        address at = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        GuestEscrow e = new GuestEscrow(address(0x7070), address(this), IGuestAttest(address(new MockGuestAttest(at))));
        transfer(e);
        vm.expectRevert("owner only"); e.setWorkload(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), true);
        vm.prank(next); e.setWorkload(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), true);
    }
    function test_usageEscrow() public {
        UsageEscrow u = new UsageEscrow(address(0x7070), address(this));
        transfer(u);
        vm.expectRevert("broker admission"); u.registerBroker(address(0xB0));
        vm.prank(next); u.registerBroker(address(0xB0));
        assertEq(u.brokerSigner(), address(0xB0));
    }
}
