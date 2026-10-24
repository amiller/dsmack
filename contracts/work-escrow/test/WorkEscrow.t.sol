// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;
import {Test} from "forge-std/Test.sol";
import {WorkEscrow} from "../src/WorkEscrow.sol";

contract Receiver {
    WorkEscrow immutable escrow;
    bool public fail;
    bool public attempted;

    constructor(WorkEscrow e) {
        escrow = e;
    }

    function setFail(bool v) external {
        fail = v;
    }

    function collect() external {
        escrow.withdraw();
    }

    receive() external payable {
        if (fail) revert();
        attempted = true;
        (bool ok,) = address(escrow).call(abi.encodeCall(escrow.withdraw, ()));
        require(!ok, "reentry unexpectedly paid");
    }
}

contract WorkEscrowTest is Test {
    WorkEscrow e;
    uint256 constant EXEC = 11;
    uint256 constant REVIEW = 12;
    uint256 constant DELIVERY = 13;
    uint256 constant ADJUDICATOR = 14;
    address owner = address(0xA11CE);
    address allocator = address(0xCAFE);
    address worker = address(0xB0B);
    WorkEscrow.Terms t;
    uint256 taskId;

    function setUp() public {
        e = new WorkEscrow();
        vm.deal(owner, 200 ether);
        t = WorkEscrow.Terms({
            packageHash: keccak256("package"),
            policyHash: keccak256("policy"),
            allocator: allocator,
            executionVerifier: vm.addr(EXEC),
            reviewer: vm.addr(REVIEW),
            deliveryVerifier: vm.addr(DELIVERY),
            adjudicator: vm.addr(ADJUDICATOR),
            effortPay: 5 ether,
            completionPay: 15 ether,
            submitSeconds: 3600,
            reviewSeconds: 86400,
            adjudicationSeconds: 86400
        });
        vm.prank(owner);
        taskId = e.createTask{value: 200 ether}(t);
    }

    function sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function reserve() internal returns (uint256 id) {
        vm.prank(allocator);
        return e.assign(taskId, worker);
    }

    function submit(uint256 id) internal {
        vm.prank(worker);
        e.submit(id, keccak256("patch"), keccak256("receipt"), keccak256("storage ack"));
    }

    function resolve(uint256 id, WorkEscrow.Outcome out, uint256 judge) internal {
        bytes32 d = e.decisionDigest(id, out);
        e.resolve(id, out, sig(EXEC, d), sig(judge, d), sig(DELIVERY, d));
    }

    function rejectResolve(uint256 id, WorkEscrow.Outcome out, uint256 judge, bytes4 error) internal {
        bytes32 d = e.decisionDigest(id, out);
        bytes memory a = sig(EXEC, d);
        bytes memory b = sig(judge, d);
        bytes memory c = sig(DELIVERY, d);
        vm.expectRevert(error);
        e.resolve(id, out, a, b, c);
    }

    function checkConservation(uint256 id) internal view {
        assertEq(
            e.task(taskId).available + e.assignment(id).reserved + e.withdrawable(worker) + e.withdrawable(owner),
            address(e).balance
        );
    }

    function testSubmittedFundsRecoverAfterBothReviewAuthoritiesDisappear() public {
        uint256 id = reserve();
        submit(id);
        uint256 cutoff = e.assignment(id).reviewBy + t.adjudicationSeconds;
        vm.warp(cutoff);
        vm.expectRevert(WorkEscrow.Deadline.selector);
        e.expireUnresolved(id);
        vm.warp(cutoff + 1);
        rejectResolve(id, WorkEscrow.Outcome.Completion, ADJUDICATOR, WorkEscrow.Deadline.selector);
        e.expireUnresolved(id);
        assertEq(uint256(e.assignment(id).state), uint256(WorkEscrow.State.Expired));
        assertEq(e.assignment(id).reserved, 0);
        assertEq(e.task(taskId).available, 200 ether);
        assertEq(e.task(taskId).activeAssignment, 0);
        assertEq(e.withdrawable(worker), 0);
        checkConservation(id);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.expireUnresolved(id);
        vm.prank(owner);
        e.closeTask(taskId);
        uint256 before = owner.balance;
        vm.prank(owner);
        e.withdraw();
        assertEq(owner.balance, before + 200 ether);
        assertEq(address(e).balance, 0);
    }

    function testAdjudicatorCanResolveAtFinalBoundaryAndRecoveryCannotPayTwice() public {
        uint256 id = reserve();
        submit(id);
        vm.warp(e.assignment(id).reviewBy + t.adjudicationSeconds);
        resolve(id, WorkEscrow.Outcome.Completion, ADJUDICATOR);
        assertEq(e.withdrawable(worker), 15 ether);
        vm.warp(block.timestamp + 1);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.expireUnresolved(id);
        checkConservation(id);
    }

    function testReviewRecoveryDoesNotExpireAReservedUnsubmittedAttempt() public {
        uint256 id = reserve();
        vm.warp(e.assignment(id).submitBy + 1);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.expireUnresolved(id);
        e.expireUnsubmitted(id);
        checkConservation(id);
    }

    function testVersionOneDomainCertificatesCannotSettleVersionTwo() public {
        uint256 id = reserve();
        submit(id);
        WorkEscrow.Assignment memory a = e.assignment(id);
        bytes32 body = keccak256(abi.encode(
            e.DECISION_TYPEHASH(), id, taskId, t.packageHash, t.policyHash,
            worker, a.candidate, a.evidence, a.delivery,
            uint8(WorkEscrow.Outcome.Completion), uint256(t.completionPay)
        ));
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("DsmackWorkEscrow"), keccak256("1"), block.chainid, address(e)
        ));
        bytes32 oldDigest = keccak256(abi.encodePacked(hex"1901", domain, body));
        assertTrue(oldDigest != e.decisionDigest(id, WorkEscrow.Outcome.Completion));
        bytes memory execution = sig(EXEC, oldDigest);
        bytes memory review = sig(REVIEW, oldDigest);
        bytes memory delivery = sig(DELIVERY, oldDigest);
        vm.expectRevert(WorkEscrow.InvalidSignature.selector);
        e.resolve(id, WorkEscrow.Outcome.Completion, execution, review, delivery);
        assertEq(uint256(e.assignment(id).state), uint256(WorkEscrow.State.Submitted));
        assertEq(e.assignment(id).reserved, 15 ether);
        assertEq(e.withdrawable(worker), 0);
        checkConservation(id);
    }

    function testAdjudicationWindowBoundsWithOtherwiseValidFundedTerms() public {
        vm.deal(owner, 600 ether);
        t.adjudicationSeconds = 0;
        vm.prank(owner);
        vm.expectRevert(WorkEscrow.InvalidTerms.selector);
        e.createTask{value: 200 ether}(t);
        t.adjudicationSeconds = uint32(30 days + 1);
        vm.prank(owner);
        vm.expectRevert(WorkEscrow.InvalidTerms.selector);
        e.createTask{value: 200 ether}(t);
        t.adjudicationSeconds = uint32(30 days);
        vm.prank(owner);
        uint256 accepted = e.createTask{value: 200 ether}(t);
        assertEq(e.task(accepted).terms.adjudicationSeconds, 30 days);
        assertEq(e.task(accepted).available, 200 ether);
    }

    function testCloseBeforeUnresolvedExpiryRecoversOnlyReturnedReservation() public {
        uint256 id = reserve();
        submit(id);
        vm.prank(owner);
        e.closeTask(taskId);
        assertEq(e.withdrawable(owner), 185 ether);
        assertEq(e.assignment(id).reserved, 15 ether);
        vm.warp(e.assignment(id).reviewBy + t.adjudicationSeconds + 1);
        vm.prank(address(0xBAD));
        e.expireUnresolved(id);
        assertEq(e.task(taskId).available, 15 ether);
        assertEq(e.withdrawable(owner), 185 ether);
        assertEq(e.withdrawable(worker), 0);
        assertFalse(e.task(taskId).open);
        vm.prank(allocator);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.assign(taskId, worker);
        vm.prank(owner);
        e.closeTask(taskId);
        vm.prank(owner);
        e.closeTask(taskId);
        assertEq(e.withdrawable(owner), 200 ether);
        checkConservation(id);
        uint256 before = owner.balance;
        vm.prank(owner);
        e.withdraw();
        assertEq(owner.balance, before + 200 ether);
        assertEq(address(e).balance, 0);
    }

    function testExpiredAssignmentCannotDisturbFreshReservation() public {
        uint256 oldId = reserve();
        submit(oldId);
        vm.warp(e.assignment(oldId).reviewBy + t.adjudicationSeconds + 1);
        e.expireUnresolved(oldId);
        uint256 freshId = reserve();
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.expireUnresolved(oldId);
        rejectResolve(oldId, WorkEscrow.Outcome.Completion, ADJUDICATOR, WorkEscrow.WrongState.selector);
        assertEq(e.task(taskId).activeAssignment, freshId);
        assertEq(e.assignment(freshId).reserved, 15 ether);
        assertEq(e.task(taskId).available, 185 ether);
        checkConservation(freshId);
    }

    function testCompletionPaysOnceAndPullWithdrawal() public {
        uint256 id = reserve();
        assertEq(e.task(taskId).available, 185 ether);
        submit(id);
        resolve(id, WorkEscrow.Outcome.Completion, REVIEW);
        assertEq(e.withdrawable(worker), 15 ether);
        assertEq(e.assignment(id).reserved, 0);
        checkConservation(id);
        rejectResolve(id, WorkEscrow.Outcome.Completion, REVIEW, WorkEscrow.WrongState.selector);
        vm.prank(worker);
        e.withdraw();
        assertEq(worker.balance, 15 ether);
    }

    function testEffortIsAlternativeNotAdditive() public {
        uint256 id = reserve();
        submit(id);
        resolve(id, WorkEscrow.Outcome.Effort, REVIEW);
        assertEq(e.withdrawable(worker), 5 ether);
        assertEq(e.task(taskId).available, 195 ether);
        checkConservation(id);
        rejectResolve(id, WorkEscrow.Outcome.Completion, REVIEW, WorkEscrow.WrongState.selector);
    }

    function testRejectNeedsJudgeButNotExecutionOrDelivery() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Reject);
        e.resolve(id, WorkEscrow.Outcome.Reject, "", sig(REVIEW, d), "");
        assertEq(e.task(taskId).available, 200 ether);
        assertEq(e.withdrawable(worker), 0);
        checkConservation(id);
    }

    function testOnlyAllocatorCanAssign() public {
        vm.expectRevert(WorkEscrow.Unauthorized.selector);
        e.assign(taskId, worker);
    }

    function testOnlyWorkerCanSubmit() public {
        uint256 id = reserve();
        vm.expectRevert(WorkEscrow.Unauthorized.selector);
        e.submit(id, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)));
    }

    function testOnlyOneActiveAssignment() public {
        reserve();
        vm.prank(allocator);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.assign(taskId, address(123));
    }

    function testCandidateCannotBeChanged() public {
        uint256 id = reserve();
        submit(id);
        vm.prank(worker);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.submit(id, keccak256("different"), keccak256("receipt"), keccak256("storage ack"));
    }

    function testNoResolveBeforeSubmission() public {
        uint256 id = reserve();
        rejectResolve(id, WorkEscrow.Outcome.Completion, REVIEW, WorkEscrow.WrongState.selector);
    }

    function testMissingDeliverySignatureCannotPay() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Completion);
        vm.expectRevert();
        e.resolve(id, WorkEscrow.Outcome.Completion, sig(EXEC, d), sig(REVIEW, d), "");
        assertEq(e.assignment(id).reserved, 15 ether);
    }

    function testWrongExecutionSignatureCannotPay() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Completion);
        vm.expectRevert(WorkEscrow.InvalidSignature.selector);
        e.resolve(id, WorkEscrow.Outcome.Completion, sig(99, d), sig(REVIEW, d), sig(DELIVERY, d));
    }

    function testSignatureCannotChangeOutcome() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Effort);
        vm.expectRevert(WorkEscrow.InvalidSignature.selector);
        e.resolve(id, WorkEscrow.Outcome.Completion, sig(EXEC, d), sig(REVIEW, d), sig(DELIVERY, d));
    }

    function testCrossContractReplayRefused() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Completion);
        WorkEscrow other = new WorkEscrow();
        vm.deal(owner, 200 ether);
        vm.prank(owner);
        uint256 tid = other.createTask{value: 200 ether}(t);
        vm.prank(allocator);
        uint256 aid = other.assign(tid, worker);
        vm.prank(worker);
        other.submit(aid, keccak256("patch"), keccak256("receipt"), keccak256("storage ack"));
        vm.expectRevert(WorkEscrow.InvalidSignature.selector);
        other.resolve(aid, WorkEscrow.Outcome.Completion, sig(EXEC, d), sig(REVIEW, d), sig(DELIVERY, d));
    }

    function testCrossChainReplayRefused() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Completion);
        vm.chainId(31338);
        vm.expectRevert(WorkEscrow.InvalidSignature.selector);
        e.resolve(id, WorkEscrow.Outcome.Completion, sig(EXEC, d), sig(REVIEW, d), sig(DELIVERY, d));
    }

    function testWrongTaskPackageRefused() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Completion);
        t.packageHash = keccak256("other package");
        vm.deal(owner, 200 ether);
        vm.prank(owner);
        uint256 tid = e.createTask{value: 200 ether}(t);
        vm.prank(allocator);
        uint256 aid = e.assign(tid, worker);
        submit(aid);
        vm.expectRevert(WorkEscrow.InvalidSignature.selector);
        e.resolve(aid, WorkEscrow.Outcome.Completion, sig(EXEC, d), sig(REVIEW, d), sig(DELIVERY, d));
    }

    function testRelayerCannotRedirectPayee() public {
        uint256 id = reserve();
        submit(id);
        bytes32 d = e.decisionDigest(id, WorkEscrow.Outcome.Completion);
        bytes memory x = sig(EXEC, d);
        bytes memory y = sig(REVIEW, d);
        bytes memory z = sig(DELIVERY, d);
        vm.prank(address(0xBAD));
        e.resolve(id, WorkEscrow.Outcome.Completion, x, y, z);
        assertEq(e.withdrawable(worker), 15 ether);
        assertEq(e.withdrawable(address(0xBAD)), 0);
    }

    function testExpiryOnlyUnsubmittedAndStrictlyAfterDeadline() public {
        uint256 id = reserve();
        vm.warp(e.assignment(id).submitBy);
        vm.expectRevert(WorkEscrow.Deadline.selector);
        e.expireUnsubmitted(id);
        vm.warp(block.timestamp + 1);
        vm.prank(worker);
        vm.expectRevert(WorkEscrow.Deadline.selector);
        e.submit(id, keccak256("p"), keccak256("e"), keccak256("d"));
        e.expireUnsubmitted(id);
        assertEq(e.task(taskId).available, 200 ether);
        checkConservation(id);
    }

    function testLateReviewPreservesFundsAndRequiresAdjudicator() public {
        uint256 id = reserve();
        vm.warp(e.assignment(id).submitBy);
        submit(id);
        vm.warp(e.assignment(id).reviewBy + 1);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.expireUnsubmitted(id);
        rejectResolve(id, WorkEscrow.Outcome.Completion, REVIEW, WorkEscrow.InvalidSignature.selector);
        assertEq(e.assignment(id).reserved, 15 ether);
        resolve(id, WorkEscrow.Outcome.Completion, ADJUDICATOR);
        checkConservation(id);
    }

    function testCloseCannotTakeReservedFunds() public {
        uint256 id = reserve();
        vm.prank(owner);
        e.closeTask(taskId);
        assertEq(e.withdrawable(owner), 185 ether);
        submit(id);
        resolve(id, WorkEscrow.Outcome.Effort, REVIEW);
        assertEq(e.task(taskId).available, 10 ether);
        vm.prank(owner);
        e.closeTask(taskId);
        assertEq(e.withdrawable(owner), 195 ether);
        checkConservation(id);
        vm.prank(allocator);
        vm.expectRevert(WorkEscrow.WrongState.selector);
        e.assign(taskId, worker);
    }

    function testBadTermsAndUnderfundingRefused() public {
        vm.deal(owner, 10 ether);
        vm.prank(owner);
        vm.expectRevert(WorkEscrow.InvalidTerms.selector);
        e.createTask{value: 10 ether}(t);
        t.effortPay = 16 ether;
        vm.expectRevert(WorkEscrow.InvalidTerms.selector);
        e.createTask(t);
    }

    function testRejectingReceiverDoesNotBlockSettlementAndCanRetry() public {
        Receiver w = new Receiver(e);
        vm.prank(allocator);
        uint256 id = e.assign(taskId, address(w));
        vm.prank(address(w));
        e.submit(id, keccak256("p"), keccak256("e"), keccak256("d"));
        resolve(id, WorkEscrow.Outcome.Completion, REVIEW);
        w.setFail(true);
        vm.expectRevert(WorkEscrow.TransferFailed.selector);
        w.collect();
        assertEq(e.withdrawable(address(w)), 15 ether);
        w.setFail(false);
        w.collect();
        assertTrue(w.attempted());
        assertEq(address(w).balance, 15 ether);
        assertEq(e.withdrawable(address(w)), 0);
    }

    function testFuzzConservationAndPayoutCap(uint96 effort, uint96 maximum, bool completion) public {
        maximum = uint96(bound(maximum, 1, 100 ether));
        effort = uint96(bound(effort, 0, maximum));
        t.effortPay = effort;
        t.completionPay = maximum;
        vm.deal(owner, maximum);
        vm.prank(owner);
        uint256 tid = e.createTask{value: maximum}(t);
        vm.prank(allocator);
        uint256 id = e.assign(tid, worker);
        submit(id);
        resolve(id, completion ? WorkEscrow.Outcome.Completion : WorkEscrow.Outcome.Effort, REVIEW);
        uint256 pay = completion ? maximum : effort;
        assertEq(e.withdrawable(worker), pay);
        assertEq(e.task(tid).available + pay, maximum);
    }
}
