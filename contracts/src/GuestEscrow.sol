// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IERC3009 {
    function authorizationState(address, bytes32) external view returns (bool);
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external;
}

/// AppleAttestRegistryV1 deployed with registry = this escrow.
interface IGuestAttest {
    function registry() external view returns (address);
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32 kid);
    function assertionEvidence(bytes32 kid) external view returns (bytes32 context, bytes32 cdhash, bytes32 rp, uint64 checkedAt, uint32 counter);
}

/// @notice UsageEscrow's deposits, terms and exit, with no broker: the Layover guest signs its own claims.
/// A guest registers an EOA by a guest Attest assertion (App Attest, verified on chain through `attest`, which admits only
/// the CDRegistry's current runner build) whose report_data is key || operator, each left-padded to 32 bytes, from an
/// owner-approved workload (os image, manifest, caller service). A claim pays when it recovers to a registered key whose
/// operator is the one the buyer's accepted terms name and whose workload is still approved.
/// Each guest key has its own cumulative per (buyer, terms hash); the sum over keys stays within the terms' cap.
contract GuestEscrow {
    uint64 public constant ESCAPE_DELAY = 14 days;
    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address operator,bytes32 termsHash,uint256 cumulativeOwed,uint64 period)");
    bytes32 public constant TERMS_TYPEHASH = keccak256("AcceptTerms(bytes32 termsHash,address operator,uint256 cap)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes constant ATTEST_DOMAIN = "dsmack.appattest.guest-attest/1";
    IERC20 public immutable token;
    address public immutable owner;
    IGuestAttest public immutable attest;
    /// The guest Attest client-data fields other than the event head and report_data.
    struct Attested { bytes32 image; bytes32 manifest; bytes32 run; bytes32 caller; }
    struct Event { string name; bytes payload; }
    struct GuestKey { address operator; bytes32 workload; bytes32 kid; bytes32 cdhash; }
    struct Terms { address operator; uint256 cap; }
    struct Paid { uint192 owed; uint64 period; }
    mapping(bytes32 => bool) public approved;
    mapping(address => GuestKey) public guestKeys;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public paid;
    mapping(address => uint256) public withdrawn;
    mapping(address => uint64) public exitRequestedAt;
    mapping(address => mapping(bytes32 => Terms)) public terms;
    mapping(address => mapping(bytes32 => uint256)) public totalClaimed;
    mapping(address => mapping(bytes32 => mapping(address => Paid))) public claimed;
    event WorkloadSet(bytes32 indexed workload, bytes32 image, bytes32 manifest, bytes32 caller, bool approved);
    event GuestKeyRegistered(address indexed key, address indexed operator, bytes32 indexed workload, bytes32 kid, bytes32 cdhash);
    event Deposited(address indexed user, uint256 amount);
    event TermsAccepted(address indexed user, bytes32 indexed termsHash, address indexed operator, uint256 cap);
    event Claimed(address indexed user, address indexed guestKey, bytes32 indexed termsHash, address operator, uint256 cumulativeOwed, uint64 period, uint256 amount);
    event ExitRequested(address indexed user, uint64 availableAt);
    event Withdrawn(address indexed user, uint256 amount);

    constructor(address token_, address owner_, IGuestAttest attest_) {
        require(token_ != address(0) && owner_ != address(0), "zero address");
        require(attest_.registry() == address(this), "attest registry");
        (token, owner, attest) = (IERC20(token_), owner_, attest_);
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
        require(user != address(0) && amount > 0 && exitRequestedAt[user] == 0, "amount or exiting");
        deposits[user] += amount;
        emit Deposited(user, amount);
    }
    /// @notice x402 top-up: executes the payer's EIP-3009 TransferWithAuthorization to this contract and credits `from`.
    function depositWithAuthorization(address from, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, bytes calldata signature) external {
        IERC3009 t = IERC3009(address(token));
        require(!t.authorizationState(from, nonce), "authorization used");
        _credit(from, value);
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        t.transferWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, v, r, s);
    }

    function claimDomain(address user) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("LayoverGuestEscrow"), keccak256("1"), block.chainid, address(this), bytes32(uint256(uint160(user)))));
    }
    function claimDigest(address user, address operator, bytes32 termsHash, uint256 cumulativeOwed, uint64 period) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", claimDomain(user), keccak256(abi.encode(CLAIM_TYPEHASH, operator, termsHash, cumulativeOwed, period))));
    }
    function termsDigest(address user, bytes32 termsHash, address operator, uint256 cap) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", claimDomain(user), keccak256(abi.encode(TERMS_TYPEHASH, termsHash, operator, cap))));
    }
    function acceptTerms(bytes32 termsHash, address operator, uint256 cap) external { _accept(msg.sender, termsHash, operator, cap); }
    function acceptTermsFor(address user, bytes32 termsHash, address operator, uint256 cap, bytes calldata signature) external {
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        require(_recover(termsDigest(user, termsHash, operator, cap), v, r, s) == user, "terms signature");
        _accept(user, termsHash, operator, cap);
    }
    function _accept(address user, bytes32 termsHash, address operator, uint256 cap) private {
        require(termsHash != 0 && operator != address(0) && cap > 0, "terms invalid");
        require(terms[user][termsHash].operator == address(0), "terms already accepted");
        terms[user][termsHash] = Terms(operator, cap);
        emit TermsAccepted(user, termsHash, operator, cap);
    }

    /// @notice `guestSig` signs Claim(operator, termsHash, cumulativeOwed, period) under claimDomain(buyer), with the
    /// operator named in the buyer's terms. cumulativeOwed is that guest key's running total for (buyer, termsHash).
    function claim(address buyer, bytes32 termsHash, uint256 cumulativeOwed, uint64 period, bytes calldata guestSig) external {
        Terms memory t = terms[buyer][termsHash];
        require(t.operator != address(0), "terms not accepted");
        require(cumulativeOwed <= t.cap, "terms cap");
        (uint8 v, bytes32 r, bytes32 s) = _split(guestSig);
        address key = _recover(claimDigest(buyer, t.operator, termsHash, cumulativeOwed, period), v, r, s);
        GuestKey memory g = guestKeys[key];
        require(g.operator != address(0), "guest key not registered");
        require(g.operator == t.operator, "terms operator");
        require(approved[g.workload], "build not approved");
        Paid memory prev = claimed[buyer][termsHash][key];
        require(period <= block.timestamp / 1 weeks && period >= prev.period, "claim period");
        uint64 exit = exitRequestedAt[buyer];
        require(exit == 0 || block.timestamp < uint256(exit) + ESCAPE_DELAY, "account exited");
        require(cumulativeOwed > prev.owed, "claim replay");
        uint256 amount = cumulativeOwed - prev.owed;
        uint256 total = totalClaimed[buyer][termsHash] + amount;
        require(total <= t.cap, "terms cap");
        require(amount <= balance(buyer), "deposit exceeded");
        claimed[buyer][termsHash][key] = Paid(uint192(cumulativeOwed), period);
        totalClaimed[buyer][termsHash] = total;
        paid[buyer] += amount;
        require(token.transfer(t.operator, amount), "token transfer");
        emit Claimed(buyer, key, termsHash, t.operator, cumulativeOwed, period, amount);
    }
    /// @notice Permanently close the account. Guests have two weeks to collect unpaid usage.
    function requestExit() external {
        require(deposits[msg.sender] > 0 && exitRequestedAt[msg.sender] == 0, "account or exit");
        exitRequestedAt[msg.sender] = uint64(block.timestamp);
        emit ExitRequested(msg.sender, uint64(block.timestamp) + ESCAPE_DELAY);
    }
    function withdraw() external {
        uint64 exit = exitRequestedAt[msg.sender];
        require(exit != 0 && block.timestamp >= uint256(exit) + ESCAPE_DELAY, "escape timeout");
        uint256 amount = balance(msg.sender);
        require(amount > 0, "empty balance");
        withdrawn[msg.sender] += amount;
        require(token.transfer(msg.sender, amount), "token transfer");
        emit Withdrawn(msg.sender, amount);
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
