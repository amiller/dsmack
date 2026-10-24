// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

/// @notice Local prototype: trusted EOA verdicts, native Anvil ETH, no Apple/GitHub verification.
contract WorkEscrow {
    enum State {
        None,
        Reserved,
        Submitted,
        Settled,
        Rejected,
        Expired
    }
    enum Outcome {
        Reject,
        Effort,
        Completion
    }

    struct Terms {
        bytes32 packageHash;
        bytes32 policyHash;
        address allocator;
        address executionVerifier;
        address reviewer;
        address deliveryVerifier;
        address adjudicator;
        uint96 effortPay;
        uint96 completionPay;
        uint32 submitSeconds;
        uint32 reviewSeconds;
        uint32 adjudicationSeconds;
    }

    struct Task {
        address requester;
        bool open;
        uint256 available;
        uint256 activeAssignment;
        Terms terms;
    }

    struct Assignment {
        uint256 taskId;
        address worker;
        State state;
        uint256 reserved;
        uint256 submitBy;
        uint256 reviewBy;
        bytes32 candidate;
        bytes32 evidence;
        bytes32 delivery;
    }
    bytes32 public constant DECISION_TYPEHASH = keccak256(
        "Decision(uint256 assignmentId,uint256 taskId,bytes32 packageHash,bytes32 policyHash,address worker,bytes32 candidate,bytes32 evidence,bytes32 delivery,uint8 outcome,uint256 payout)"
    );
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 public nextTask = 1;
    uint256 public nextAssignment = 1;
    mapping(uint256 => Task) private tasks;
    mapping(uint256 => Assignment) private assignments;
    mapping(address => uint256) public withdrawable;
    bool private withdrawing;

    error Unauthorized();
    error InvalidTerms();
    error WrongState();
    error Deadline();
    error InsufficientBudget();
    error InvalidSignature();
    error TransferFailed();

    event TaskCreated(
        uint256 indexed taskId, address indexed requester, bytes32 packageHash, bytes32 policyHash, uint256 funding
    );
    event Assigned(
        uint256 indexed assignmentId, uint256 indexed taskId, address indexed worker, uint256 reserved, uint256 submitBy
    );
    event Submitted(
        uint256 indexed assignmentId, bytes32 candidate, bytes32 evidence, bytes32 delivery, uint256 reviewBy
    );
    event Resolved(uint256 indexed assignmentId, Outcome outcome, uint256 payout);
    event Expired(uint256 indexed assignmentId);
    event ReviewExpired(uint256 indexed assignmentId, uint256 returned);
    event TaskClosed(uint256 indexed taskId, uint256 reclaimed);
    event Withdrawn(address indexed account, uint256 amount);

    function createTask(Terms calldata terms) external payable returns (uint256 id) {
        if (
            terms.packageHash == 0 || terms.policyHash == 0 || terms.allocator == address(0)
                || terms.executionVerifier == address(0) || terms.reviewer == address(0)
                || terms.deliveryVerifier == address(0) || terms.adjudicator == address(0) || terms.completionPay == 0
                || terms.effortPay > terms.completionPay || terms.submitSeconds == 0 || terms.submitSeconds > 7 days
                || terms.reviewSeconds == 0 || terms.reviewSeconds > 30 days || terms.adjudicationSeconds == 0
                || terms.adjudicationSeconds > 30 days || msg.value < terms.completionPay
        ) revert InvalidTerms();
        id = nextTask++;
        Task storage t = tasks[id];
        t.requester = msg.sender;
        t.open = true;
        t.available = msg.value;
        t.terms = terms;
        emit TaskCreated(id, msg.sender, terms.packageHash, terms.policyHash, msg.value);
    }

    function task(uint256 id) external view returns (Task memory) {
        return tasks[id];
    }

    function assignment(uint256 id) external view returns (Assignment memory) {
        return assignments[id];
    }

    /// @dev Named allocator authorizes assignment. No permissionless first-claim monopoly.
    function assign(uint256 taskId, address worker) external returns (uint256 id) {
        Task storage t = tasks[taskId];
        if (msg.sender != t.terms.allocator) revert Unauthorized();
        if (!t.open || t.activeAssignment != 0 || worker == address(0)) revert WrongState();
        uint256 reserve = t.terms.completionPay;
        if (t.available < reserve) revert InsufficientBudget();
        id = nextAssignment++;
        t.available -= reserve;
        t.activeAssignment = id;
        Assignment storage a = assignments[id];
        a.taskId = taskId;
        a.worker = worker;
        a.state = State.Reserved;
        a.reserved = reserve;
        a.submitBy = block.timestamp + t.terms.submitSeconds;
        emit Assigned(id, taskId, worker, reserve, a.submitBy);
    }

    /// @notice Commitments are claims pending signatures, not proof of execution or availability.
    function submit(uint256 id, bytes32 candidate, bytes32 evidence, bytes32 delivery) external {
        Assignment storage a = assignments[id];
        if (msg.sender != a.worker) revert Unauthorized();
        if (a.state != State.Reserved) revert WrongState();
        if (block.timestamp > a.submitBy) revert Deadline();
        if (candidate == 0 || evidence == 0 || delivery == 0) revert InvalidTerms();
        a.state = State.Submitted;
        a.candidate = candidate;
        a.evidence = evidence;
        a.delivery = delivery;
        a.reviewBy = block.timestamp + tasks[a.taskId].terms.reviewSeconds;
        emit Submitted(id, candidate, evidence, delivery, a.reviewBy);
    }

    function decisionDigest(uint256 id, Outcome outcome) public view returns (bytes32) {
        Assignment storage a = assignments[id];
        Task storage t = tasks[a.taskId];
        uint256 pay =
            outcome == Outcome.Completion ? t.terms.completionPay : outcome == Outcome.Effort ? t.terms.effortPay : 0;
        bytes32 body = keccak256(
            abi.encode(
                DECISION_TYPEHASH,
                id,
                a.taskId,
                t.terms.packageHash,
                t.terms.policyHash,
                a.worker,
                a.candidate,
                a.evidence,
                a.delivery,
                uint8(outcome),
                pay
            )
        );
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("DsmackWorkEscrow"), keccak256("2"), block.chainid, address(this))
        );
        return keccak256(abi.encodePacked(hex"1901", domain, body));
    }

    /// @dev Anyone may relay, but payout always goes to the assigned worker.
    /// After review expiry only the preselected adjudicator can authorize the verdict.
    function resolve(
        uint256 id,
        Outcome outcome,
        bytes calldata executionSig,
        bytes calldata reviewSig,
        bytes calldata deliverySig
    ) external {
        Assignment storage a = assignments[id];
        if (a.state != State.Submitted) revert WrongState();
        Task storage t = tasks[a.taskId];
        if (block.timestamp > a.reviewBy + t.terms.adjudicationSeconds) revert Deadline();
        bytes32 digest = decisionDigest(id, outcome);
        address judge = block.timestamp <= a.reviewBy ? t.terms.reviewer : t.terms.adjudicator;
        if (ECDSA.recover(digest, reviewSig) != judge) revert InvalidSignature();
        uint256 pay;
        if (outcome != Outcome.Reject) {
            if (
                ECDSA.recover(digest, executionSig) != t.terms.executionVerifier
                    || ECDSA.recover(digest, deliverySig) != t.terms.deliveryVerifier
            ) revert InvalidSignature();
            pay = outcome == Outcome.Completion ? t.terms.completionPay : t.terms.effortPay;
        }
        uint256 reserved = a.reserved;
        a.reserved = 0;
        a.state = outcome == Outcome.Reject ? State.Rejected : State.Settled;
        t.activeAssignment = 0;
        t.available += reserved - pay;
        withdrawable[a.worker] += pay;
        emit Resolved(id, outcome, pay);
    }

    /// @notice Financial expiry only; does not stop a VM or establish termination.
    function expireUnsubmitted(uint256 id) external {
        Assignment storage a = assignments[id];
        if (a.state != State.Reserved) revert WrongState();
        if (block.timestamp <= a.submitBy) revert Deadline();
        Task storage t = tasks[a.taskId];
        t.available += a.reserved;
        t.activeAssignment = 0;
        a.reserved = 0;
        a.state = State.Expired;
        emit Expired(id);
    }

    /// @notice Fixed, permissionless last resort after both review windows.
    /// @dev This refunds the reservation to task funds, never awards success.
    /// The requester must close/withdraw to receive funds. A submitted candidate
    /// remains evidence; expiration does not grant rights to it or stop a VM.
    function expireUnresolved(uint256 id) external {
        Assignment storage a = assignments[id];
        if (a.state != State.Submitted) revert WrongState();
        Task storage t = tasks[a.taskId];
        if (block.timestamp <= a.reviewBy + t.terms.adjudicationSeconds) revert Deadline();
        uint256 returned = a.reserved;
        t.available += returned;
        t.activeAssignment = 0;
        a.reserved = 0;
        a.state = State.Expired;
        emit ReviewExpired(id, returned);
    }

    /// @notice Can be repeated to reclaim returned funds after an outstanding assignment resolves.
    function closeTask(uint256 id) external {
        Task storage t = tasks[id];
        if (msg.sender != t.requester) revert Unauthorized();
        t.open = false;
        uint256 amount = t.available;
        t.available = 0;
        withdrawable[msg.sender] += amount;
        emit TaskClosed(id, amount);
    }

    /// @dev Pull payments: a failing recipient cannot prevent resolution or another withdrawal.
    function withdraw() external {
        if (withdrawing) revert WrongState();
        uint256 amount = withdrawable[msg.sender];
        if (amount == 0) revert InsufficientBudget();
        withdrawing = true;
        withdrawable[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
        withdrawing = false;
        emit Withdrawn(msg.sender, amount);
    }
}
