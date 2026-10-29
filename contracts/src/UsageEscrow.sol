// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Base Sepolia usage escrow. Owner admits immutable node classes; a pinned broker binds attested runs;
/// guests sign cumulative EIP-712 usage. Congestion premiums have no withdrawal path.
contract UsageEscrow {
    uint256 public constant CHAIN_ID = 84532;
    uint64 public constant EPOCH_SECONDS = 60;
    uint64 public constant PURCHASE_SECONDS = 3600;
    uint64 public constant SETTLEMENT_GRACE = 3600;
    uint128 public constant MAX_BYTES = 64 * 1024 * 1024;
    uint128 public constant MAX_SECONDS = 600;
    uint128 public constant MAX_TOKENS = 10_000_000;
    bytes32 public constant RECEIPT_TYPEHASH =
        keccak256("Receipt(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Node {
        address operator;
        uint8 unit;
        uint128 floorPrice;
        uint128 target;
        uint128 price;
        uint128 booked;
        uint64 epoch;
        bytes32 composeHash;
        bytes32 imageHash;
    }

    struct PurchaseData {
        bytes32 node;
        address payer;
        bytes32 buyerKey;
        address operator;
        uint8 unit;
        uint128 amount;
        uint128 price;
        uint128 floorPrice;
        uint64 boughtAt;
        uint64 expires;
        uint64 sequence;
        uint128 used;
        uint64 endedAt;
        bool closed;
        bytes32 bindingHash;
    }

    struct Receipt {
        uint256 purchaseId;
        uint64 sequence;
        uint128 used;
        uint64 endedAt;
        bool finalReceipt;
    }

    struct NodeBinding {
        bytes32 node;
        address operator;
        address receiptSigner;
        bytes32 composeHash;
        bytes32 imageHash;
        bytes32 runId;
        uint64 expires;
    }
    bytes32 public constant BINDING_TYPEHASH = keccak256("NodeBinding(bytes32 node,address operator,address receiptSigner,bytes32 composeHash,bytes32 imageHash,bytes32 runId,uint64 expires)");
    address public brokerSigner;
    event BrokerRegistered(address broker);
    address public immutable owner;
    mapping(bytes32 => Node) private nodes;
    mapping(uint256 => PurchaseData) private purchases;
    mapping(address => uint256) public credits;
    uint256 public lockedPremium;
    uint256 public nextPurchaseId = 1;

    event NodeRegistered(bytes32 indexed node, address indexed operator, uint8 unit,
        uint128 floorPrice, uint128 target, bytes32 composeHash, bytes32 imageHash);
    event PriceUpdated(bytes32 indexed node, uint64 epoch, uint128 price);
    event Purchase(
        uint256 indexed purchaseId,
        bytes32 indexed node,
        address indexed payer,
        bytes32 buyerKey,
        uint8 unit,
        uint128 amount,
        uint128 price,
        uint64 expires
    );
    event Settled(
        uint256 indexed purchaseId,
        uint64 sequence,
        uint128 used,
        uint256 operatorCredit,
        uint256 premium,
        bool finalReceipt
    );
    event Refunded(uint256 indexed purchaseId, address indexed payer, uint256 amount);
    event Withdrawn(address indexed payee, uint256 amount);

    constructor(address owner_) {
        require(block.chainid == CHAIN_ID, "Base Sepolia only");
        require(owner_ != address(0), "zero owner");
        owner = owner_;
    }

    /// @notice Pin the admission authority once, before selling any class.
    function registerBroker(address broker) external {
        require(msg.sender == owner && brokerSigner == address(0) && broker != address(0), "broker admission");
        brokerSigner = broker;
        emit BrokerRegistered(broker);
    }

    /// @notice Classes outlive runs; registration and purchases finish before VM launch.
    function registerNode(bytes32 node, address operator, uint8 unit, uint128 floorPrice,
        uint128 target, bytes32 composeHash, bytes32 imageHash) external {
        require(msg.sender == owner, "owner only");
        require(brokerSigner != address(0), "broker missing");
        require(node != bytes32(0) && nodes[node].operator == address(0), "node exists or zero");
        require(operator != address(0), "zero address");
        require(composeHash != bytes32(0) && imageHash != bytes32(0), "missing measurements");
        require(unit <= 2, "unit");
        require(floorPrice > 0 && floorPrice <= type(uint128).max / 16, "floor");
        require(target > 0 && target <= type(uint128).max / 2, "target");
        nodes[node] = Node(operator, unit, floorPrice, target, floorPrice, 0,
            uint64(block.timestamp / EPOCH_SECONDS), composeHash, imageHash);
        emit NodeRegistered(node, operator, unit, floorPrice, target, composeHash, imageHash);
    }

    function getNode(bytes32 node) external view returns (Node memory) {
        return nodes[node];
    }

    function getPurchase(uint256 id) external view returns (PurchaseData memory) {
        return purchases[id];
    }

    /// @notice Price after applying all completed epochs, without changing state.
    function quote(bytes32 node) public view returns (uint128 price) {
        Node memory n = nodes[node];
        require(n.operator != address(0), "unknown node");
        return _price(n, uint64(block.timestamp / EPOCH_SECONDS));
    }

    function checkpoint(bytes32 node) public {
        Node storage n = nodes[node];
        require(n.operator != address(0), "unknown node");
        uint64 epoch = uint64(block.timestamp / EPOCH_SECONDS);
        if (epoch == n.epoch) return;
        n.price = _price(n, epoch);
        n.epoch = epoch;
        n.booked = 0;
        emit PriceUpdated(node, epoch, n.price);
    }

    // Funded reservations provide utilization immediately, without trusting
    // when an operator submits receipts. Idle epochs decay; at most ~30
    // iterations are needed between the 16x ceiling and floor.
    function _price(Node memory n, uint64 epoch) private pure returns (uint128 price) {
        price = n.price;
        if (epoch == n.epoch) return price;
        uint256 target = n.target;
        uint256 load = n.booked;
        uint256 difference = load >= target ? load - target : target - load;
        uint256 change = uint256(price) * difference / target / 8;
        uint256 next = load >= target ? uint256(price) + change : uint256(price) - change;
        uint256 floor = n.floorPrice;
        uint256 ceiling = floor * 16;
        price = uint128(next < floor ? floor : next > ceiling ? ceiling : next);
        uint64 idle = epoch - n.epoch - 1;
        while (idle > 0 && price > floor) {
            uint256 lower = uint256(price) - uint256(price) / 8;
            // Small integer prices can have a zero step; further empty epochs
            // then have exactly the same result, so stop instead of looping.
            if (lower == price) break;
            price = uint128(lower < floor ? floor : lower);
            --idle;
        }
    }

    function buy(bytes32 node, uint8 unit, uint128 amount, bytes32 buyerKey) external payable returns (uint256 id) {
        checkpoint(node);
        Node storage n = nodes[node];
        require(unit == n.unit, "unit");
        require(amount > 0 && amount <= (unit == 0 ? MAX_BYTES : unit == 1 ? MAX_SECONDS : MAX_TOKENS), "amount");
        require(buyerKey != bytes32(0), "buyer key");
        require(msg.value == uint256(amount) * n.price, "exact price");
        uint64 boughtAt = uint64(block.timestamp);
        uint64 expires = boughtAt + PURCHASE_SECONDS;
        id = nextPurchaseId++;
        purchases[id] = PurchaseData(
            node,
            msg.sender,
            buyerKey,
            n.operator,
            unit,
            amount,
            n.price,
            n.floorPrice,
            boughtAt,
            expires,
            0,
            0,
            boughtAt,
            false,
            bytes32(0)
        );
        uint256 booked = uint256(n.booked) + amount;
        uint256 capacity = uint256(n.target) * 2;
        n.booked = uint128(booked > capacity ? capacity : booked);
        emit Purchase(id, node, msg.sender, buyerKey, unit, amount, n.price, expires);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("DsmackUsageEscrow"), keccak256("2"), block.chainid, address(this))
        );
    }

    function receiptDigest(Receipt memory r) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR(),
                keccak256(abi.encode(RECEIPT_TYPEHASH, r.purchaseId, r.sequence, r.used, r.endedAt, r.finalReceipt))
            )
        );
    }

    function bindingDigest(NodeBinding memory b) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(),
            keccak256(abi.encode(BINDING_TYPEHASH, b.node, b.operator, b.receiptSigner,
                b.composeHash, b.imageHash, b.runId, b.expires))));
    }

    function recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        require(signature.length == 65, "signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        require(uint256(s) <= HALF_ORDER && (v == 27 || v == 28), "signature canonical");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "zero signer");
        return signer;
    }

    function settle(Receipt[] calldata receipts, bytes[] calldata signatures,
        NodeBinding calldata b, bytes calldata brokerSignature) external {
        require(receipts.length == signatures.length && receipts.length > 0, "receipt lengths");
        bytes32 digest = bindingDigest(b);
        require(recover(digest, brokerSignature) == brokerSigner, "broker signer");
        Node storage n = nodes[b.node];
        require(n.operator != address(0) && b.operator == n.operator, "binding operator");
        require(b.composeHash == n.composeHash && b.imageHash == n.imageHash, "binding measurements");
        require(b.receiptSigner != address(0) && b.runId != bytes32(0), "binding run");
        for (uint256 i; i < receipts.length; ++i) _settle(receipts[i], signatures[i], b, digest);
    }

    function _settle(Receipt calldata r, bytes calldata signature, NodeBinding calldata b, bytes32 digest) private {
        PurchaseData storage p = purchases[r.purchaseId];
        require(p.payer != address(0) && !p.closed, "purchase closed or unknown");
        require(p.node == b.node && p.operator == b.operator, "binding class");
        require(p.bindingHash == bytes32(0) || p.bindingHash == digest, "binding changed");
        require(block.timestamp < uint256(p.expires) + SETTLEMENT_GRACE, "settlement expired");
        require(r.sequence > p.sequence && r.used >= p.used && r.used <= p.amount, "usage or sequence");
        require(r.endedAt >= p.endedAt && r.endedAt <= p.expires && r.endedAt <= block.timestamp && r.endedAt <= b.expires, "receipt time");
        require(recover(receiptDigest(r), signature) == b.receiptSigner, "receipt signer");
        p.bindingHash = digest;
        uint256 delta = uint256(r.used) - p.used;
        uint256 operatorCredit = delta * p.floorPrice;
        uint256 premium = delta * (p.price - p.floorPrice);
        p.sequence = r.sequence;
        p.used = r.used;
        p.endedAt = r.endedAt;
        credits[p.operator] += operatorCredit;
        lockedPremium += premium;
        emit Settled(r.purchaseId, r.sequence, r.used, operatorCredit, premium, r.finalReceipt);
        if (r.finalReceipt) _refund(r.purchaseId, p);
    }

    function refund(uint256 id) external {
        PurchaseData storage p = purchases[id];
        require(p.payer != address(0) && !p.closed, "purchase closed or unknown");
        require(block.timestamp >= uint256(p.expires) + SETTLEMENT_GRACE, "refund not ready");
        _refund(id, p);
    }

    function _refund(uint256 id, PurchaseData storage p) private {
        p.closed = true;
        uint256 amount = (uint256(p.amount) - p.used) * p.price;
        credits[p.payer] += amount;
        emit Refunded(id, p.payer, amount);
    }

    function withdraw() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "no credit");
        credits[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
        emit Withdrawn(msg.sender, amount);
    }
}
