// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import "../src/LayoverCredit.sol";

contract LayoverCreditTest is Test {
    LayoverCredit c;
    address owner = address(0x1FBe);
    uint256 payerKey = 0xA11CE;
    address payer;
    address bob = address(0xB0B);

    function setUp() public {
        vm.warp(1000);
        c = new LayoverCredit(owner);
        payer = vm.addr(payerKey);
        vm.prank(owner); c.mint(payer, 100e6);
    }
    function auth(bytes32 typehash, address to, uint256 value, uint256 before, bytes32 nonce) internal view returns (uint8, bytes32, bytes32) {
        bytes32 h = keccak256(abi.encode(typehash, payer, to, value, 0, before, nonce));
        return vm.sign(payerKey, keccak256(abi.encodePacked("\x19\x01", c.DOMAIN_SEPARATOR(), h)));
    }

    function testNoGenesisAndMetadata() public {
        LayoverCredit fresh = new LayoverCredit(owner);
        assertEq(fresh.totalSupply(), 0);
        assertEq(fresh.balanceOf(owner), 0);
        assertEq(c.decimals(), 6);
        assertEq(c.symbol(), "LAYC");
        assertEq(c.CAP(), 21_000_000e6);
    }
    function testZeroOwnerReverts() public {
        vm.expectRevert("owner");
        new LayoverCredit(address(0));
    }
    function testMintWithinEpochRewardOnly() public {
        vm.expectRevert("owner only");
        c.mint(bob, 1);
        vm.startPrank(owner);
        c.mint(bob, 6_900e6);
        vm.expectRevert("epoch reward");
        c.mint(bob, 188e6);
        c.mint(bob, 187e6);
        vm.expectRevert("period not over");
        c.advanceEpoch();
        vm.warp(block.timestamp + 1 days);
        c.advanceEpoch();
        vm.expectRevert("period not over");
        c.advanceEpoch();
        c.mint(bob, 7_187e6);
        vm.stopPrank();
        assertEq(c.balanceOf(bob), 7_087e6 + 7_187e6); // setUp minted 100 to the payer in epoch 0
    }
    function testHalvingSchedule() public view {
        assertEq(c.reward(0), 7_187e6);
        assertEq(c.reward(1460), 7_187e6);
        assertEq(c.reward(1461), 3_593.5e6);
        assertEq(c.reward(1461 * 2), 1_796.75e6);
        assertEq(c.reward(1461 * 300), 0);
    }
    function testCapBindsAcrossEpochs() public {
        LayoverCredit full = new LayoverCredit(owner);
        vm.store(address(full), bytes32(0), bytes32(uint256(21_000_000e6 - 5e6))); // totalSupply, slot 0
        vm.startPrank(owner);
        full.mint(bob, 5e6);
        vm.expectRevert(bytes("cap"));
        full.mint(bob, 1);
        vm.stopPrank();
        assertEq(full.totalSupply(), full.CAP());
    }
    function testAdvanceEpochOwnerOnly() public {
        vm.expectRevert("owner only");
        c.advanceEpoch();
    }
    function testTransferWithAuthorizationOnce() public {
        bytes32 nonce = keccak256("n1");
        (uint8 v, bytes32 r, bytes32 s) = auth(c.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), bob, 10e6, 2000, nonce);
        c.transferWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
        assertEq(c.balanceOf(bob), 10e6);
        assertTrue(c.authorizationState(payer, nonce));
        vm.expectRevert("authorization used");
        c.transferWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
    }
    function testAuthorizationRefusals() public {
        bytes32 nonce = keccak256("n2");
        (uint8 v, bytes32 r, bytes32 s) = auth(c.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), bob, 10e6, 2000, nonce);
        vm.expectRevert("invalid signature");
        c.transferWithAuthorization(payer, bob, 11e6, 0, 2000, nonce, v, r, s);
        vm.warp(2000);
        vm.expectRevert("authorization time");
        c.transferWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
    }
    function testReceiveWithAuthorizationOnlyPayee() public {
        bytes32 nonce = keccak256("n3");
        (uint8 v, bytes32 r, bytes32 s) = auth(c.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(), bob, 10e6, 2000, nonce);
        vm.expectRevert("caller must be the payee");
        c.receiveWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
        // A receive authorization is not a transfer authorization.
        vm.expectRevert("invalid signature");
        c.transferWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
        vm.prank(bob); c.receiveWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
        assertEq(c.balanceOf(bob), 10e6);
    }
    function testCancelAuthorization() public {
        bytes32 nonce = keccak256("n4");
        (uint8 v, bytes32 r, bytes32 s) = auth(c.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), bob, 10e6, 2000, nonce);
        (uint8 cv, bytes32 cr, bytes32 cs) = vm.sign(payerKey, keccak256(abi.encodePacked("\x19\x01", c.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(c.CANCEL_AUTHORIZATION_TYPEHASH(), payer, nonce)))));
        c.cancelAuthorization(payer, nonce, cv, cr, cs);
        vm.expectRevert("authorization used");
        c.transferWithAuthorization(payer, bob, 10e6, 0, 2000, nonce, v, r, s);
    }
    function testTransferFromAllowance() public {
        vm.prank(payer); c.approve(bob, 5e6);
        vm.startPrank(bob);
        c.transferFrom(payer, bob, 5e6);
        vm.expectRevert();
        c.transferFrom(payer, bob, 1);
        vm.stopPrank();
    }
}
