// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {CouponIssuanceGuardExperiment} from "../src/application/CouponIssuanceGuardExperiment.sol";

contract CouponIssuanceGuardExperimentTest is Test {
    CouponIssuanceGuardExperiment guard;
    CouponIssuanceGuardExperiment.Attempt attempt;
    address issuer = address(100);
    bytes32 coupon = bytes32(uint256(1));
    bytes32 policy = bytes32(uint256(2));

    function setUp() public {
        guard = new CouponIssuanceGuardExperiment(issuer, policy);
        attempt = CouponIssuanceGuardExperiment.Attempt(bytes32(uint256(3)), bytes32(uint256(4)), bytes32(uint256(5)));
    }

    function testOnlyIssuerCanConsumeAndFailedCallerDoesNotReserve() public {
        vm.expectRevert("issuer"); guard.consume(coupon, attempt);
        assertEq(guard.consumed(coupon), bytes32(0));
        vm.prank(issuer);
        assertEq(guard.consume(coupon, attempt), guard.commitment(coupon, attempt));
    }

    function testExactlyOneAttemptEvenWhenRecipientOfferOrProcessChanges() public {
        vm.prank(issuer); bytes32 original = guard.consume(coupon, attempt);
        for (uint256 i; i < 4; i++) {
            if (i == 1) attempt.recipient = bytes32(uint256(30));
            if (i == 2) attempt.offer = bytes32(uint256(40));
            if (i == 3) attempt.processNonce = bytes32(uint256(50));
            vm.prank(issuer); vm.expectRevert("already consumed"); guard.consume(coupon, attempt);
        }
        assertEq(guard.consumed(coupon), original);
    }

    function testInvalidBindingDoesNotConsume() public {
        bytes32 saved = attempt.processNonce;
        attempt.processNonce = 0;
        vm.prank(issuer); vm.expectRevert("binding"); guard.consume(coupon, attempt);
        assertEq(guard.consumed(coupon), bytes32(0));
        attempt.processNonce = saved;
        vm.prank(issuer); guard.consume(coupon, attempt);
    }

    function testDifferentCouponsRemainIndependent() public {
        vm.prank(issuer); guard.consume(coupon, attempt);
        bytes32 another = bytes32(uint256(10));
        vm.prank(issuer); guard.consume(another, attempt);
        assertTrue(guard.consumed(coupon) != guard.consumed(another));
    }

    function testNoExpiryOrResetAfterAbandonedAttempt() public {
        vm.prank(issuer); bytes32 original = guard.consume(coupon, attempt);
        vm.warp(block.timestamp + 365 days);
        vm.prank(issuer); vm.expectRevert("already consumed"); guard.consume(coupon, attempt);
        assertEq(guard.consumed(coupon), original);
    }

    function testCommitmentBindsEveryFieldAndAuthorityDomain() public {
        bytes32 original = guard.commitment(coupon, attempt);
        attempt.recipient = bytes32(uint256(30)); assertTrue(guard.commitment(coupon, attempt) != original); attempt.recipient = bytes32(uint256(3));
        attempt.offer = bytes32(uint256(40)); assertTrue(guard.commitment(coupon, attempt) != original); attempt.offer = bytes32(uint256(4));
        attempt.processNonce = bytes32(uint256(50)); assertTrue(guard.commitment(coupon, attempt) != original); attempt.processNonce = bytes32(uint256(5));
        assertTrue(guard.commitment(bytes32(uint256(99)), attempt) != original);
        uint256 chain = block.chainid; vm.chainId(chain + 1);
        assertTrue(guard.commitment(coupon, attempt) != original); vm.chainId(chain);
        CouponIssuanceGuardExperiment other = new CouponIssuanceGuardExperiment(issuer, policy);
        assertTrue(other.commitment(coupon, attempt) != original);
        // Keep the address fixed while changing embedded immutable bytecode.
        // vm.etch is a test-only domain-isolation check, not a runtime upgrade.
        other = new CouponIssuanceGuardExperiment(address(101), policy);
        vm.etch(address(guard), address(other).code);
        assertTrue(guard.commitment(coupon, attempt) != original);
        other = new CouponIssuanceGuardExperiment(issuer, bytes32(uint256(22)));
        vm.etch(address(guard), address(other).code);
        assertTrue(guard.commitment(coupon, attempt) != original);
    }

    function testRejectEmptyAuthorityOrPolicy() public {
        vm.expectRevert("configuration"); new CouponIssuanceGuardExperiment(address(0), policy);
        vm.expectRevert("configuration"); new CouponIssuanceGuardExperiment(issuer, bytes32(0));
    }
}
