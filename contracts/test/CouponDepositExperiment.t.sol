// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {CouponDepositExperiment, ICouponSettlementVerifier} from "../src/application/CouponDepositExperiment.sol";

// Explicit synthetic authorization oracle. This proves escrow mechanics, not attestation.
contract SyntheticCouponVerifier is ICouponSettlementVerifier {
    bytes32 public accepted;
    bool public unavailable;
    function accept(bytes32 digest) external { accepted = digest; }
    function setUnavailable(bool value) external { unavailable = value; }
    function verify(bytes32 digest, bytes calldata proof) external view returns (bool) {
        require(!unavailable, "verifier offline");
        return digest == accepted && keccak256(proof) == keccak256("synthetic-only");
    }
}
contract AdversarialCouponSponsor {
    CouponDepositExperiment public escrow;
    bool public reject;
    bool public reenter;
    bool public reentrySucceeded;
    uint256 public received;
    constructor(CouponDepositExperiment e) { escrow = e; }
    function configure(bool reject_, bool reenter_) external { reject = reject_; reenter = reenter_; }
    function fund(bytes32 coupon, bytes32 scope) external returns (bytes32) {
        return escrow.fund{value: 1 ether}(coupon, scope);
    }
    function withdraw() external { escrow.withdraw(); }
    receive() external payable {
        require(!reject, "reject transfer");
        received += msg.value;
        if (reenter) {
            (reentrySucceeded,) = address(escrow).call(abi.encodeCall(escrow.withdraw, ()));
        }
    }
}
contract CouponDepositExperimentTest is Test {
    SyntheticCouponVerifier verifier;
    CouponDepositExperiment escrow;
    CouponDepositExperiment.Statement s;
    address sponsor = address(100);
    function setUp() public {
        vm.warp(1000);
        verifier = new SyntheticCouponVerifier();
        escrow = new CouponDepositExperiment(verifier, bytes32(uint256(1)), 5e9, 300);
        vm.deal(sponsor, 2 ether);
        vm.prank(sponsor);
        bytes32 id = escrow.fund{value: 1 ether}(bytes32(uint256(2)), bytes32(uint256(3)));
        s = CouponDepositExperiment.Statement(id, bytes32(uint256(2)), bytes32(uint256(3)),
            bytes32(uint256(4)), bytes32(uint256(5)), bytes32(uint256(6)), bytes32(uint256(7)),
            5e9, 1000, 1000, true);
        verifier.accept(escrow.statementDigest(s));
    }
    function testReleaseOnceAndOnlySponsorWithdraws() public {
        escrow.release(s, "synthetic-only");
        assertEq(escrow.withdrawable(sponsor), 1 ether);
        vm.expectRevert("deposit"); escrow.release(s, "synthetic-only");
        vm.expectRevert("no released funds"); escrow.withdraw();
        vm.prank(sponsor); escrow.withdraw();
        assertEq(sponsor.balance, 2 ether);
        assertEq(address(escrow).balance, 0);
        vm.prank(sponsor); vm.expectRevert("no released funds"); escrow.withdraw();
    }
    function testNoOwnerOrTimeoutRefund() public {
        vm.warp(1000000);
        vm.prank(sponsor); vm.expectRevert("no released funds"); escrow.withdraw();
        assertEq(address(escrow).balance, 1 ether);
    }
    function testRejectUnattestedOrWrongProof() public {
        vm.expectRevert("unverified"); escrow.release(s, "local-unattested");
        verifier.accept(bytes32(0));
        vm.expectRevert("unverified"); escrow.release(s, "synthetic-only");
    }
    function testRejectWrongAttribution() public {
        s.providerScope = bytes32(uint256(9));
        vm.expectRevert("attribution"); escrow.release(s, "synthetic-only");
        s.providerScope = bytes32(uint256(3)); s.coupon = bytes32(uint256(9));
        vm.expectRevert("attribution"); escrow.release(s, "synthetic-only");
    }
    function testRejectChangedKeyRecipientCiphertextOrReceipt() public {
        s.providerKey = bytes32(uint256(9));
        vm.expectRevert("unverified"); escrow.release(s, "synthetic-only");
        s.providerKey = bytes32(uint256(4)); s.recipient = bytes32(uint256(9));
        vm.expectRevert("unverified"); escrow.release(s, "synthetic-only");
        s.recipient = bytes32(uint256(5)); s.delivery = bytes32(uint256(9));
        vm.expectRevert("unverified"); escrow.release(s, "synthetic-only");
        s.delivery = bytes32(uint256(6)); s.issuanceReceipt = bytes32(uint256(9));
        vm.expectRevert("unverified"); escrow.release(s, "synthetic-only");
    }
    function testRejectStaleFutureAndPredepositIssuance() public {
        vm.warp(1301); vm.expectRevert("stale"); escrow.release(s, "synthetic-only");
        vm.warp(999); vm.expectRevert(bytes("time")); escrow.release(s, "synthetic-only");
        vm.warp(1000); s.issuedAt = 999;
        vm.expectRevert(bytes("time")); escrow.release(s, "synthetic-only");
    }
    function testRejectIncompleteAndCorrectedBelowThreshold() public {
        s.finalAccounting = false;
        vm.expectRevert("accounting"); escrow.release(s, "synthetic-only");
        s.finalAccounting = true; s.eligibleNetNanoUsd = 5e9 - 1;
        verifier.accept(escrow.statementDigest(s));
        vm.expectRevert("accounting"); escrow.release(s, "synthetic-only");
    }
    function testBindChainContractAndPolicy() public {
        bytes32 original = escrow.statementDigest(s);
        vm.chainId(block.chainid + 1);
        assertTrue(original != escrow.statementDigest(s));
        vm.expectRevert("unverified"); escrow.release(s, "synthetic-only");
        CouponDepositExperiment other = new CouponDepositExperiment(verifier, bytes32(uint256(8)), 5e9, 300);
        assertTrue(original != other.statementDigest(s));
    }
    function testProviderKeyCannotReleaseSecondDeposit() public {
        escrow.release(s, "synthetic-only");
        vm.prank(sponsor);
        s.depositId = escrow.fund{value: 1 ether}(bytes32(uint256(8)), s.providerScope);
        s.coupon = bytes32(uint256(8));
        verifier.accept(escrow.statementDigest(s));
        vm.expectRevert("key already settled"); escrow.release(s, "synthetic-only");
    }
    function testOtherSponsorCannotReserveDepositId() public {
        vm.deal(address(this), 1 ether);
        bytes32 id = escrow.fund{value: 1 ether}(s.coupon, s.providerScope);
        assertTrue(id != s.depositId);
        vm.prank(sponsor); vm.expectRevert("already funded");
        escrow.fund{value: 1}(s.coupon, s.providerScope);
    }
    function testVerifierFailurePreservesAllObligations() public {
        verifier.setUnavailable(true);
        vm.expectRevert("verifier offline"); escrow.release(s, "synthetic-only");
        (address owner, uint256 amount,,,, bool released) = escrow.deposits(s.depositId);
        assertEq(owner, sponsor); assertEq(amount, 1 ether); assertFalse(released);
        assertEq(escrow.withdrawable(sponsor), 0);
        assertFalse(escrow.usedProviderKeys(keccak256(abi.encode(s.providerScope, s.providerKey))));
        assertEq(address(escrow).balance, 1 ether);
        verifier.setUnavailable(false);
        escrow.release(s, "synthetic-only");
        assertEq(escrow.withdrawable(sponsor), 1 ether);
    }
    function fundedAdversary() internal returns (AdversarialCouponSponsor a) {
        a = new AdversarialCouponSponsor(escrow);
        vm.deal(address(a), 1 ether);
        s.depositId = a.fund(s.coupon, s.providerScope);
        verifier.accept(escrow.statementDigest(s));
        escrow.release(s, "synthetic-only");
    }
    function testRejectedTransferPreservesCreditForLaterRecovery() public {
        AdversarialCouponSponsor a = fundedAdversary();
        a.configure(true, false);
        vm.expectRevert("transfer"); a.withdraw();
        assertEq(escrow.withdrawable(address(a)), 1 ether);
        assertEq(address(escrow).balance, 2 ether);
        a.configure(false, false); a.withdraw();
        assertEq(escrow.withdrawable(address(a)), 0);
        assertEq(a.received(), 1 ether);
        assertEq(address(escrow).balance, 1 ether);
    }
    function testReentrantWithdrawalCannotSpendCreditTwice() public {
        AdversarialCouponSponsor a = fundedAdversary();
        a.configure(false, true); a.withdraw();
        assertFalse(a.reentrySucceeded());
        assertEq(a.received(), 1 ether);
        assertEq(escrow.withdrawable(address(a)), 0);
        assertEq(address(escrow).balance, 1 ether);
    }
    function testEachDomainParameterIndependentlyChangesDigest() public {
        bytes32 original = escrow.statementDigest(s);
        bytes memory originalCode = address(escrow).code;
        CouponDepositExperiment other = new CouponDepositExperiment(verifier, bytes32(uint256(1)), 5e9, 300);
        assertTrue(other.statementDigest(s) != original); // address alone
        other = new CouponDepositExperiment(verifier, bytes32(uint256(2)), 5e9, 300);
        vm.etch(address(escrow), address(other).code); // keep address and storage; change one immutable
        assertTrue(escrow.statementDigest(s) != original);
        vm.etch(address(escrow), originalCode);
        other = new CouponDepositExperiment(new SyntheticCouponVerifier(), bytes32(uint256(1)), 5e9, 300);
        vm.etch(address(escrow), address(other).code);
        assertTrue(escrow.statementDigest(s) != original);
        vm.etch(address(escrow), originalCode);
        other = new CouponDepositExperiment(verifier, bytes32(uint256(1)), 5e9 + 1, 300);
        vm.etch(address(escrow), address(other).code);
        assertTrue(escrow.statementDigest(s) != original);
        vm.etch(address(escrow), originalCode);
        other = new CouponDepositExperiment(verifier, bytes32(uint256(1)), 5e9, 301);
        vm.etch(address(escrow), address(other).code);
        assertTrue(escrow.statementDigest(s) != original);
        vm.etch(address(escrow), originalCode);
        assertEq(escrow.statementDigest(s), original);
    }
}
