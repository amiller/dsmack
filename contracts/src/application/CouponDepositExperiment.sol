// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// A verdict must verify private issuance AND final eligible provider accounting.
/// No implementation or production attestation authority is supplied here.
interface ICouponSettlementVerifier {
    function verify(bytes32 statementDigest, bytes calldata proof) external view returns (bool);
}

/// Offline settlement mechanics only. Deploying with a permissive verifier is unsafe.
/// Immutable policy; no administrator withdrawal, timeout refund or upgrade bypass.
contract CouponDepositExperiment {
    bytes32 public constant DOMAIN = keccak256("dsmack-coupon-deposit-experiment-v1");
    ICouponSettlementVerifier public immutable verifier;
    bytes32 public immutable policyHash;
    uint256 public immutable thresholdNanoUsd;
    uint64 public immutable maxObservationAge;

    struct Deposit {
        address sponsor;
        uint256 amount;
        bytes32 coupon;
        bytes32 providerScope;
        uint64 fundedAt;
        bool released;
    }
    struct Statement {
        bytes32 depositId;
        bytes32 coupon;
        bytes32 providerScope;
        bytes32 providerKey;
        bytes32 recipient;
        bytes32 delivery;
        bytes32 issuanceReceipt;
        uint256 eligibleNetNanoUsd;
        uint64 issuedAt;
        uint64 observedAt;
        bool finalAccounting;
    }
    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => bool) public usedProviderKeys;
    mapping(address => uint256) public withdrawable;
    event Funded(bytes32 indexed depositId, address indexed sponsor, bytes32 coupon, uint256 amount);
    event Released(bytes32 indexed depositId, bytes32 statementDigest);
    event Withdrawn(address indexed sponsor, uint256 amount);

    constructor(ICouponSettlementVerifier verifier_, bytes32 policy_, uint256 threshold_, uint64 maxAge_) {
        require(address(verifier_).code.length != 0 && policy_ != 0 && threshold_ > 0 && maxAge_ > 0, "policy");
        verifier = verifier_;
        policyHash = policy_;
        thresholdNanoUsd = threshold_;
        maxObservationAge = maxAge_;
    }

    function fund(bytes32 coupon, bytes32 providerScope) external payable returns (bytes32 id) {
        require(msg.value > 0 && coupon != 0 && providerScope != 0, "funding");
        // A different sponsor cannot reserve this sponsor's deposit identifier.
        id = keccak256(abi.encode(msg.sender, coupon));
        require(deposits[id].sponsor == address(0), "already funded");
        deposits[id] = Deposit(msg.sender, msg.value, coupon, providerScope, uint64(block.timestamp), false);
        emit Funded(id, msg.sender, coupon, msg.value);
    }

    function statementDigest(Statement calldata s) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), address(verifier),
            policyHash, thresholdNanoUsd, maxObservationAge, s));
    }

    function release(Statement calldata s, bytes calldata proof) external {
        Deposit storage d = deposits[s.depositId];
        require(d.sponsor != address(0) && !d.released, "deposit");
        require(s.coupon == d.coupon && s.providerScope == d.providerScope, "attribution");
        require(s.providerKey != 0 && s.recipient != 0 && s.delivery != 0 && s.issuanceReceipt != 0, "issuance");
        require(s.issuedAt >= d.fundedAt && s.observedAt >= s.issuedAt && s.observedAt <= block.timestamp, "time");
        require(block.timestamp - s.observedAt <= maxObservationAge, "stale");
        require(s.finalAccounting && s.eligibleNetNanoUsd >= thresholdNanoUsd, "accounting");
        bytes32 key = keccak256(abi.encode(s.providerScope, s.providerKey));
        require(!usedProviderKeys[key], "key already settled");
        bytes32 digest = statementDigest(s);
        // external view compiles to STATICCALL; verifier cannot mutate this escrow.
        require(verifier.verify(digest, proof), "unverified");
        d.released = true;
        usedProviderKeys[key] = true;
        withdrawable[d.sponsor] += d.amount;
        emit Released(s.depositId, digest);
    }

    function withdraw() external {
        uint256 amount = withdrawable[msg.sender];
        require(amount > 0, "no released funds");
        withdrawable[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer");
        emit Withdrawn(msg.sender, amount);
    }
}
