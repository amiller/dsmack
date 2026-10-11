// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// Irreversible attempt journal only. Does not authenticate a TEE, finalize a
/// chain, prevent live memory cloning, or itself authorize provider creation.
contract CouponIssuanceGuardExperiment {
    bytes32 public constant DOMAIN = keccak256("dsmack-coupon-issuance-attempt-v1");
    address public immutable issuer;
    bytes32 public immutable policyHash;

    struct Attempt {
        bytes32 recipient;
        bytes32 offer;
        bytes32 processNonce;
    }
    mapping(bytes32 => bytes32) public consumed;
    event AttemptConsumed(bytes32 indexed coupon, bytes32 indexed commitment);

    constructor(address issuer_, bytes32 policy_) {
        require(issuer_ != address(0) && policy_ != 0, "configuration");
        issuer = issuer_;
        policyHash = policy_;
    }

    function commitment(bytes32 coupon, Attempt calldata attempt) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), issuer,
            policyHash, coupon, attempt));
    }

    /// Caller must be the measured service's independently admitted transaction
    /// authority. Never use a sponsor-controlled EOA as evidence of private issuance.
    function consume(bytes32 coupon, Attempt calldata attempt) external returns (bytes32 digest) {
        require(msg.sender == issuer, "issuer");
        require(coupon != 0 && attempt.recipient != 0 && attempt.offer != 0 && attempt.processNonce != 0, "binding");
        require(consumed[coupon] == 0, "already consumed");
        digest = commitment(coupon, attempt);
        require(digest != 0, "commitment");
        consumed[coupon] = digest;
        emit AttemptConsumed(coupon, digest);
    }
}
