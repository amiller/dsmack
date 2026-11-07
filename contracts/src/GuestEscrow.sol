// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Owned} from "./Owned.sol";

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IERC3009 {
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external;
}

/// AppleAttestRegistryV1 deployed with registry = this escrow.
interface IGuestAttest {
    function registry() external view returns (address);
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32 kid);
    function assertionEvidence(bytes32 kid) external view returns (bytes32 context, bytes32 cdhash, bytes32 rp, uint64 checkedAt, uint32 counter);
}

/// @notice UsageEscrow's deposits and terms, with no broker: the Layover guest signs its own claims.
/// A guest registers an EOA by a guest Attest assertion (App Attest, verified on chain through `attest`, which admits only
/// the CDRegistry's current runner build) whose report_data is key || operator, each left-padded to 32 bytes, from an
/// owner-approved workload (os image, manifest, caller service). A claim pays when it recovers to a registered key whose
/// operator is the one the buyer's accepted terms name and whose workload is still approved.
/// Each guest key has its own cumulative per (buyer, terms hash); the sum over keys stays within the terms' cap.
/// The buyer withdraws any time down to its exposure, the sum over unreleased terms of cap - totalClaimed. Closing terms
/// keeps them claimable for CLAIM_GRACE; after that `release` (run inside withdraw) drops their remainder from exposure.
contract GuestEscrow is Owned {
    uint64 public constant CLAIM_GRACE = 1 days;
    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address operator,bytes32 termsHash,uint256 cumulativeOwed)");
    bytes32 public constant TERMS_TYPEHASH = keccak256("AcceptTerms(bytes32 termsHash,address operator,uint256 cap,uint256 deadline)");
    bytes32 public constant CLOSE_TYPEHASH = keccak256("CloseTerms(bytes32 termsHash,uint256 deadline)");
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256("Withdraw(address to,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes constant ATTEST_DOMAIN = "dsmack.appattest.guest-attest/1";
    IERC20 public immutable token;
    IGuestAttest public immutable attest;
    /// The guest Attest client-data fields other than the event head and report_data.
    struct Attested { bytes32 image; bytes32 manifest; bytes32 run; bytes32 caller; }
    struct Event { string name; bytes payload; }
    struct GuestKey { address operator; bytes32 workload; bytes32 kid; bytes32 cdhash; }
    struct Terms { address operator; uint256 cap; uint64 closedAt; bool released; }
    mapping(bytes32 => bool) public approved;
    mapping(address => GuestKey) public guestKeys;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public paid;
    mapping(address => uint256) public withdrawn;
    mapping(address => uint256) public exposure;
    mapping(address => uint256) public withdrawNonce;
    mapping(address => mapping(bytes32 => Terms)) public terms;
    mapping(address => mapping(bytes32 => uint256)) public totalClaimed;
    mapping(address => mapping(bytes32 => mapping(address => uint256))) public claimed;
    event WorkloadSet(bytes32 indexed workload, bytes32 image, bytes32 manifest, bytes32 caller, bool approved);
    event GuestKeyRegistered(address indexed key, address indexed operator, bytes32 indexed workload, bytes32 kid, bytes32 cdhash);
    event Deposited(address indexed user, uint256 amount);
    event TermsAccepted(address indexed user, bytes32 indexed termsHash, address indexed operator, uint256 cap);
    event Claimed(address indexed user, address indexed guestKey, bytes32 indexed termsHash, address operator, uint256 cumulativeOwed, uint256 amount);
    event TermsClosed(address indexed user, bytes32 indexed termsHash, uint64 claimableUntil);
    event Released(address indexed user, bytes32 indexed termsHash, uint256 remainder);
    event Withdrawn(address indexed user, address indexed to, uint256 amount);

    constructor(address token_, address owner_, IGuestAttest attest_) Owned(owner_) {
        require(token_ != address(0) && owner_ != address(0), "zero address");
        require(attest_.registry() == address(this), "attest registry");
        (token, attest) = (IERC20(token_), attest_);
    }

    function workloadId(bytes32 image, bytes32 manifest, bytes32 caller) public pure returns (bytes32) {
        return keccak256(abi.encode(image, manifest, caller));
    }
    /// @notice Approve or remove a guest build. Removing one stops claims by every key registered under it.
    function setWorkload(bytes32 image, bytes32 manifest, bytes32 caller, bool ok) external {
        require(msg.sender == owner, "owner only");
        require(image != 0 && manifest != 0 && caller != 0, "workload");
        bytes32 w = workloadId(image, manifest, caller);
        approved[w] = ok;
        emit WorkloadSet(w, image, manifest, caller, ok);
    }

    /// @notice Anyone may submit. `proof` is the AppleAttest proof of the guest Attest assertion whose client data is
    /// rebuilt from `a`, the event log (ending in its only system-ready) and report_data = key || operator.
    function registerGuestKey(address key, address operator, Attested calldata a, Event[] calldata events, bytes calldata proof) external {
        require(key != address(0) && operator != address(0), "zero address");
        require(guestKeys[key].operator == address(0), "key registered");
        bytes32 w = workloadId(a.image, a.manifest, a.caller);
        require(approved[w], "build not approved");
        bytes memory reportData = abi.encode(key, operator);
        bytes32 kid = attest.verify(sha256(abi.encodePacked(ATTEST_DOMAIN, a.image, a.manifest, a.run, eventHead(events), a.caller, reportData)), proof);
        (, bytes32 cdhash,,,) = attest.assertionEvidence(kid);
        guestKeys[key] = GuestKey(operator, w, kid, cdhash);
        emit GuestKeyRegistered(key, operator, w, kid, cdhash);
    }
    function eventHead(Event[] calldata events) public pure returns (bytes32 head) {
        for (uint256 i; i < events.length; i++) {
            bytes calldata n = bytes(events[i].name);
            bytes calldata p = events[i].payload;
            require((keccak256(n) == keccak256("system-ready")) == (i == events.length - 1), "system-ready last");
            head = sha256(abi.encodePacked(head, sha256(abi.encodePacked(uint32(n.length), n, uint32(p.length), p))));
        }
        require(events.length > 0, "system-ready last");
    }

    function balance(address user) public view returns (uint256) { return deposits[user] - paid[user] - withdrawn[user]; }
    function deposit(uint256 amount) external { _pull(msg.sender, msg.sender, amount); }
    function depositFor(address user, uint256 amount) external { _pull(msg.sender, user, amount); }
    function _pull(address from, address user, uint256 amount) private {
        _credit(user, amount);
        require(token.transferFrom(from, address(this), amount), "token transfer");
    }
    function _credit(address user, uint256 amount) private {
        require(user != address(0) && amount > 0, "amount");
        deposits[user] += amount;
        emit Deposited(user, amount);
    }
    /// @notice Top-up: executes the payer's EIP-3009 ReceiveWithAuthorization (to = this escrow) and credits `from`.
    /// Only the payee may execute a ReceiveWithAuthorization, so nobody can land the transfer on the token directly and
    /// leave it uncredited.
    function depositWithAuthorization(address from, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, bytes calldata signature) external {
        _credit(from, value);
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        IERC3009(address(token)).receiveWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, v, r, s);
    }

    function claimDomain(address user) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("LayoverGuestEscrow"), keccak256("1"), block.chainid, address(this), bytes32(uint256(uint160(user)))));
    }
    function claimDigest(address user, address operator, bytes32 termsHash, uint256 cumulativeOwed) public view returns (bytes32) {
        return _digest(user, keccak256(abi.encode(CLAIM_TYPEHASH, operator, termsHash, cumulativeOwed)));
    }
    function _digest(address user, bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", claimDomain(user), structHash));
    }
    /// Relayed AcceptTerms, CloseTerms and Withdraw signatures carry a deadline (unix seconds); past it they are refused.
    function termsDigest(address user, bytes32 termsHash, address operator, uint256 cap, uint256 deadline) public view returns (bytes32) {
        return _digest(user, keccak256(abi.encode(TERMS_TYPEHASH, termsHash, operator, cap, deadline)));
    }
    function closeDigest(address user, bytes32 termsHash, uint256 deadline) public view returns (bytes32) {
        return _digest(user, keccak256(abi.encode(CLOSE_TYPEHASH, termsHash, deadline)));
    }
    function withdrawDigest(address user, address to, uint256 amount, uint256 nonce, uint256 deadline) public view returns (bytes32) {
        return _digest(user, keccak256(abi.encode(WITHDRAW_TYPEHASH, to, amount, nonce, deadline)));
    }
    function _signed(address user, bytes32 digest, uint256 deadline, bytes calldata signature, string memory what) private view {
        require(block.timestamp <= deadline, "signature expired");
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        require(_recover(digest, v, r, s) == user, what);
    }
    function acceptTerms(bytes32 termsHash, address operator, uint256 cap) external { _accept(msg.sender, termsHash, operator, cap); }
    function acceptTermsFor(address user, bytes32 termsHash, address operator, uint256 cap, uint256 deadline, bytes calldata signature) external {
        _signed(user, termsDigest(user, termsHash, operator, cap, deadline), deadline, signature, "terms signature");
        _accept(user, termsHash, operator, cap);
    }
    function _accept(address user, bytes32 termsHash, address operator, uint256 cap) private {
        require(termsHash != 0 && operator != address(0) && cap > 0, "terms invalid");
        require(terms[user][termsHash].operator == address(0), "terms already accepted");
        terms[user][termsHash] = Terms(operator, cap, 0, false);
        exposure[user] += cap;
        require(exposure[user] <= balance(user), "terms unfunded");
        emit TermsAccepted(user, termsHash, operator, cap);
    }

    /// @notice `guestSig` signs Claim(operator, termsHash, cumulativeOwed) under claimDomain(buyer), with the
    /// operator named in the buyer's terms. cumulativeOwed is that guest key's running total for (buyer, termsHash).
    function claim(address buyer, bytes32 termsHash, uint256 cumulativeOwed, bytes calldata guestSig) external {
        Terms memory t = terms[buyer][termsHash];
        require(t.operator != address(0), "terms not accepted");
        require(t.closedAt == 0 || block.timestamp < uint256(t.closedAt) + CLAIM_GRACE, "terms closed");
        require(cumulativeOwed <= t.cap, "terms cap");
        (uint8 v, bytes32 r, bytes32 s) = _split(guestSig);
        address key = _recover(claimDigest(buyer, t.operator, termsHash, cumulativeOwed), v, r, s);
        GuestKey memory g = guestKeys[key];
        require(g.operator != address(0), "guest key not registered");
        require(g.operator == t.operator, "terms operator");
        require(approved[g.workload], "build not approved");
        uint256 prev = claimed[buyer][termsHash][key];
        require(cumulativeOwed > prev, "claim replay");
        uint256 amount = cumulativeOwed - prev;
        uint256 total = totalClaimed[buyer][termsHash] + amount;
        require(total <= t.cap, "terms cap");
        require(amount <= balance(buyer), "deposit exceeded");
        claimed[buyer][termsHash][key] = cumulativeOwed;
        totalClaimed[buyer][termsHash] = total;
        exposure[buyer] -= amount;
        paid[buyer] += amount;
        require(token.transfer(t.operator, amount), "token transfer");
        emit Claimed(buyer, key, termsHash, t.operator, cumulativeOwed, amount);
    }

    /// @notice Stop new exposure on these terms. Guests may still claim for CLAIM_GRACE.
    function closeTerms(bytes32 termsHash) external { _close(msg.sender, termsHash); }
    function closeTermsFor(address user, bytes32 termsHash, uint256 deadline, bytes calldata signature) external {
        _signed(user, closeDigest(user, termsHash, deadline), deadline, signature, "close signature");
        _close(user, termsHash);
    }
    function _close(address user, bytes32 termsHash) private {
        Terms storage t = terms[user][termsHash];
        require(t.operator != address(0) && t.closedAt == 0, "terms not open");
        t.closedAt = uint64(block.timestamp);
        emit TermsClosed(user, termsHash, uint64(block.timestamp) + CLAIM_GRACE);
    }

    /// @notice Withdraw down to exposure, to the caller. `expired` are closed terms past their grace to drop from exposure first.
    function withdraw(uint256 amount, bytes32[] calldata expired) external { _withdraw(msg.sender, msg.sender, amount, expired); }
    /// @notice Relayed withdrawal: `user` signs Withdraw(to, amount, nonce, deadline) with its current withdrawNonce. Every
    /// withdrawal, direct or relayed, uses up the nonce, so a direct withdraw voids any outstanding relayed one.
    function withdrawFor(address user, address to, uint256 amount, uint256 deadline, bytes calldata signature, bytes32[] calldata expired) external {
        _signed(user, withdrawDigest(user, to, amount, withdrawNonce[user], deadline), deadline, signature, "withdraw signature");
        _withdraw(user, to, amount, expired);
    }
    function _withdraw(address user, address to, uint256 amount, bytes32[] calldata expired) private {
        withdrawNonce[user]++;
        for (uint256 i; i < expired.length; i++) {
            Terms storage t = terms[user][expired[i]];
            require(t.closedAt != 0 && !t.released && block.timestamp >= uint256(t.closedAt) + CLAIM_GRACE, "not expired");
            t.released = true;
            uint256 rest = t.cap - totalClaimed[user][expired[i]];
            exposure[user] -= rest;
            emit Released(user, expired[i], rest);
        }
        require(to != address(0) && amount > 0 && amount + exposure[user] <= balance(user), "above withdrawable");
        withdrawn[user] += amount;
        require(token.transfer(to, amount), "token transfer");
        emit Withdrawn(user, to, amount);
    }
    function withdrawable(address user) external view returns (uint256) {
        uint256 b = balance(user);
        return b > exposure[user] ? b - exposure[user] : 0;
    }

    function _split(bytes calldata signature) private pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "signature length");
        assembly ("memory-safe") { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
    }
    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) private pure returns (address signer) {
        require(uint256(s) <= HALF_ORDER && (v == 27 || v == 28), "signature canonical");
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "zero signer");
    }
}
