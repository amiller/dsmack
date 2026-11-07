// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {GuestEscrow} from "../src/GuestEscrow.sol";
import {GuestEscrowBase, MockGuestAttest} from "./GuestEscrow.t.sol";

/// Properties the contract should have and, on escrow-terms, does not (notes/contract-security-20261106.md in souk-co/layover).
contract GuestEscrowFindingsTest is GuestEscrowBase {
    uint256 payerKey = 0xA11CE;
    address payer;

    function setUp() public {
        vm.warp(30 weeks);
        deploy(new MockGuestAttest(vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 2)));
        payer = vm.addr(payerKey);
        token.transfer(payer, 100e6);
        token.transfer(buyer, 100e6);
    }
    function authorization(bytes32 typehash, uint256 value, bytes32 nonce) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 h = keccak256(abi.encode(typehash, payer, address(esc), value, 0, block.timestamp + 1 hours, nonce));
        return vm.sign(payerKey, keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), h)));
    }

    /// Finding 1: whoever sees the payer's EIP-3009 authorization can execute it on the token first. The tokens reach the
    /// escrow, the nonce is spent, depositWithAuthorization then reverts, and nothing credits or returns the tokens.
    function testFrontRunAuthorizationDoesNotStrandTokens() public {
        bytes32 nonce = keccak256("x402");
        (uint8 v, bytes32 r, bytes32 s) = authorization(token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(), 10e6, nonce);
        vm.prank(address(0xBAD));
        (bool frontRun,) = address(token).call(abi.encodeCall(token.transferWithAuthorization,
            (payer, address(esc), 10e6, 0, block.timestamp + 1 hours, nonce, v, r, s)));
        vm.prank(address(0xBAD));
        (bool frontRunReceive,) = address(token).call(abi.encodeCall(token.receiveWithAuthorization,
            (payer, address(esc), 10e6, 0, block.timestamp + 1 hours, nonce, v, r, s)));
        if (!frontRun && !frontRunReceive) esc.depositWithAuthorization(payer, 10e6, 0, block.timestamp + 1 hours, nonce, abi.encodePacked(r, s, v));
        assertEq(token.balanceOf(address(esc)), esc.balance(payer), "escrow holds tokens no account is credited with");
        assertEq(esc.balance(payer), 10e6);
    }

    /// Finding 2: acceptTerms raises exposure without checking the balance covers it, so two operators can each be shown
    /// fully funded terms and the second one's claim cannot be paid.
    function testAcceptedTermsAreFunded() public {
        vm.startPrank(buyer);
        token.approve(address(esc), 50e6); esc.deposit(50e6);
        esc.acceptTerms(keccak256("a"), operator, 50e6);
        vm.expectRevert("terms unfunded");
        esc.acceptTerms(keccak256("b"), other, 50e6);
        vm.stopPrank();
        assertLe(esc.exposure(buyer), esc.balance(buyer));
    }
}
