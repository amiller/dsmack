// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

/// @notice Prepaid USDC accounts. Amounts on chain are USDC base units (6 decimals).
/// Claims are cumulative per user/operator; the user's address salts the EIP-712 domain.
contract UsageEscrow {
    uint64 public constant ESCAPE_DELAY = 14 days;
    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address operator,uint256 cumulativeOwed,uint64 period)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    IERC20 public immutable token;
    address public immutable owner;
    address public brokerSigner;
    struct Node { address operator; uint8 unit; bytes32 composeHash; bytes32 imageHash; }
    struct Claim { address operator; uint256 cumulativeOwed; uint64 period; }
    mapping(bytes32 => Node) private nodes;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public paid;
    mapping(address => uint256) public withdrawn;
    mapping(address => uint64) public exitRequestedAt;
    mapping(address => mapping(address => uint256)) public claimed;
    mapping(address => mapping(address => uint64)) public claimPeriod;
    event Deposited(address indexed user, uint256 amount);
    event Claimed(address indexed user, address indexed operator, uint256 cumulativeOwed, uint64 period);
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
    function deposit(uint256 amount) external {
        require(amount > 0 && exitRequestedAt[msg.sender] == 0, "amount or exiting");
        deposits[msg.sender] += amount;
        require(token.transferFrom(msg.sender, address(this), amount), "USDC transfer");
        emit Deposited(msg.sender, amount);
    }
    function claimDomain(address user) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("DsmackPrepaid"), keccak256("1"), block.chainid, address(this), bytes32(uint256(uint160(user)))));
    }
    function claimDigest(address user, Claim memory c) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", claimDomain(user), keccak256(abi.encode(CLAIM_TYPEHASH, c.operator, c.cumulativeOwed, c.period))));
    }
    function claim(address user, Claim calldata c, bytes calldata signature) external {
        require(signature.length == 65, "signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly ("memory-safe") { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
        require(uint256(s) <= HALF_ORDER && (v == 27 || v == 28), "signature canonical");
        address signer = ecrecover(claimDigest(user, c), v, r, s);
        require(signer != address(0) && signer == brokerSigner, "broker signature");
        require(c.operator != address(0) && c.period < block.timestamp / 1 weeks && c.period >= claimPeriod[user][c.operator], "claim period");
        uint64 exit = exitRequestedAt[user];
        require(exit == 0 || block.timestamp < uint256(exit) + ESCAPE_DELAY, "account exited");
        uint256 previous = claimed[user][c.operator];
        require(c.cumulativeOwed > previous, "claim replay");
        uint256 amount = c.cumulativeOwed - previous;
        require(amount <= balance(user), "deposit exceeded");
        claimed[user][c.operator] = c.cumulativeOwed;
        claimPeriod[user][c.operator] = c.period;
        paid[user] += amount;
        require(token.transfer(c.operator, amount), "USDC transfer");
        emit Claimed(user, c.operator, c.cumulativeOwed, c.period);
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
        require(token.transfer(msg.sender, amount), "USDC transfer");
        emit Withdrawn(msg.sender, amount);
    }
}
