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

/// @notice Prepaid token accounts (6-decimal base units). A user accepts terms (operator, cap) under a terms hash;
/// the broker signs cumulative claims per user and terms hash, and the user's address salts the EIP-712 domain.
contract UsageEscrow {
    uint64 public constant ESCAPE_DELAY = 14 days;
    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address operator,bytes32 termsHash,uint256 cumulativeOwed,uint64 period)");
    bytes32 public constant TERMS_TYPEHASH = keccak256("AcceptTerms(bytes32 termsHash,address operator,uint256 cap)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    IERC20 public immutable token;
    address public immutable owner;
    address public brokerSigner;
    struct Node { address operator; uint8 unit; bytes32 composeHash; bytes32 imageHash; }
    struct Claim { address operator; bytes32 termsHash; uint256 cumulativeOwed; uint64 period; }
    struct Terms { address operator; uint256 cap; }
    mapping(bytes32 => Node) private nodes;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public paid;
    mapping(address => uint256) public withdrawn;
    mapping(address => uint64) public exitRequestedAt;
    mapping(address => mapping(bytes32 => Terms)) public terms;
    mapping(address => mapping(bytes32 => uint256)) public claimed;
    mapping(address => mapping(bytes32 => uint64)) public claimPeriod;
    event Deposited(address indexed user, uint256 amount);
    event TermsAccepted(address indexed user, bytes32 indexed termsHash, address indexed operator, uint256 cap);
    event Claimed(address indexed user, address indexed operator, bytes32 indexed termsHash, uint256 cumulativeOwed, uint64 period);
    event BrokerRotated(address indexed previous, address indexed broker);
    event ExitRequested(address indexed user, uint64 availableAt);
    event Withdrawn(address indexed user, uint256 amount);
    event NodeRegistered(bytes32 indexed node, address indexed operator, uint8 unit, bytes32 composeHash, bytes32 imageHash);

    constructor(address token_, address owner_) {
        require(token_ != address(0) && owner_ != address(0), "zero address");
        token = IERC20(token_); owner = owner_;
    }
    function registerBroker(address broker) external {
        require(msg.sender == owner && brokerSigner == address(0) && broker != address(0), "broker admission");
        brokerSigner = broker;
        emit BrokerRotated(address(0), broker);
    }
    /// @notice Replace the claim signer, immediately. Signed but unsubmitted claims stop verifying (the broker can re-sign
    /// its accruals). The owner, like the signer, can pay out at most each buyer's accepted caps, and only to the operator
    /// each accepted terms hash names.
    function rotateBroker(address broker) external {
        require(msg.sender == owner && brokerSigner != address(0) && broker != address(0) && broker != brokerSigner, "broker rotation");
        emit BrokerRotated(brokerSigner, broker);
        brokerSigner = broker;
    }
    function registerNode(bytes32 node, address operator, uint8 unit, bytes32 composeHash, bytes32 imageHash) external {
        require(msg.sender == owner, "owner only");
        require(node != 0 && nodes[node].operator == address(0) && operator != address(0), "node admission");
        require(unit <= 1 && composeHash != 0 && imageHash != 0, "node measurements/unit");
        nodes[node] = Node(operator, unit, composeHash, imageHash);
        emit NodeRegistered(node, operator, unit, composeHash, imageHash);
    }
    function getNode(bytes32 node) external view returns (Node memory) { return nodes[node]; }
    function balance(address user) public view returns (uint256) { return deposits[user] - paid[user] - withdrawn[user]; }

    function deposit(uint256 amount) external { _pull(msg.sender, msg.sender, amount); }
    /// @notice A sponsor pays from its own tokens into another user's account.
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
    /// An authorization someone else already executed (or cancelled) is refused: its tokens, if any, are not credited.
    function depositWithAuthorization(address from, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, bytes calldata signature) external {
        IERC3009 t = IERC3009(address(token));
        require(!t.authorizationState(from, nonce), "authorization used");
        _credit(from, value);
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        t.transferWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, v, r, s);
    }

    function claimDomain(address user) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("DsmackPrepaid"), keccak256("1"), block.chainid, address(this), bytes32(uint256(uint160(user)))));
    }
    function claimDigest(address user, Claim memory c) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", claimDomain(user), keccak256(abi.encode(CLAIM_TYPEHASH, c.operator, c.termsHash, c.cumulativeOwed, c.period))));
    }
    function termsDigest(address user, bytes32 termsHash, address operator, uint256 cap) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", claimDomain(user), keccak256(abi.encode(TERMS_TYPEHASH, termsHash, operator, cap))));
    }
    /// @notice Acceptance is final per terms hash; new terms (another cap or operator) need a new hash.
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

    function claim(address user, Claim calldata c, bytes calldata signature) external {
        // Terms are checked before the signature so anyone can show an over-cap claim reverting "terms cap".
        Terms memory t = terms[user][c.termsHash];
        require(t.operator != address(0), "terms not accepted");
        require(c.operator == t.operator, "terms operator");
        require(c.cumulativeOwed <= t.cap, "terms cap");
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        require(_recover(claimDigest(user, c), v, r, s) == brokerSigner, "broker signature");
        require(c.period <= block.timestamp / 1 weeks && c.period >= claimPeriod[user][c.termsHash], "claim period");
        uint64 exit = exitRequestedAt[user];
        require(exit == 0 || block.timestamp < uint256(exit) + ESCAPE_DELAY, "account exited");
        uint256 previous = claimed[user][c.termsHash];
        require(c.cumulativeOwed > previous, "claim replay");
        uint256 amount = c.cumulativeOwed - previous;
        require(amount <= balance(user), "deposit exceeded");
        claimed[user][c.termsHash] = c.cumulativeOwed;
        claimPeriod[user][c.termsHash] = c.period;
        paid[user] += amount;
        require(token.transfer(c.operator, amount), "token transfer");
        emit Claimed(user, c.operator, c.termsHash, c.cumulativeOwed, c.period);
    }
    /// @notice Permanently close the account. Operators have two weeks to collect unpaid usage.
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
