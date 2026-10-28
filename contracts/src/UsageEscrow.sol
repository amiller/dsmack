// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Base Sepolia usage escrow. Owner admits attested, immutable node runs;
/// guests sign cumulative EIP-712 usage. Congestion premiums have no withdrawal path.
contract UsageEscrow {
    uint256 public constant CHAIN_ID = 84532;
    uint64 public constant EPOCH_SECONDS = 60;
    uint64 public constant PURCHASE_SECONDS = 3600;
    uint64 public constant SETTLEMENT_GRACE = 3600;
    uint128 public constant MAX_BYTES = 64 * 1024 * 1024;
    uint128 public constant MAX_SECONDS = 600;
    bytes32 public constant RECEIPT_TYPEHASH =
        keccak256("Receipt(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Node {
        address operator;
        address receiptSigner;
        bytes32 attestationHash;
        uint8 unit;
        uint128 floorPrice;
        uint128 target;
        uint128 price;
        uint128 booked;
        uint64 epoch;
        uint64 runExpires;
    }

    struct PurchaseData {
        bytes32 node;
        address payer;
        bytes32 buyerKey;
        address operator;
        address receiptSigner;
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
    }

    struct Receipt {
        uint256 purchaseId;
        uint64 sequence;
        uint128 used;
        uint64 endedAt;
        bool finalReceipt;
    }

    address public immutable owner;
    mapping(bytes32 => Node) private nodes;
    mapping(uint256 => PurchaseData) private purchases;
    mapping(address => uint256) public credits;
    uint256 public lockedPremium;
    uint256 public nextPurchaseId = 1;

    event NodeRegistered(
        bytes32 indexed node,
        address indexed operator,
        address receiptSigner,
        bytes32 attestationHash,
        uint8 unit,
        uint128 floorPrice,
        uint128 target,
        uint64 runExpires
    );
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

    /// @dev The owner verifies Apple/guest evidence off chain, including the
    /// receiptSigner binding. New runs need new node IDs; there is no mutation.
    function registerNode(
        bytes32 node,
        address operator,
        address receiptSigner,
        bytes32 attestationHash,
        uint8 unit,
        uint128 floorPrice,
        uint128 target,
        uint64 runExpires
    ) external {
        require(msg.sender == owner, "owner only");
        require(node != bytes32(0) && nodes[node].operator == address(0), "node exists or zero");
        require(operator != address(0) && receiptSigner != address(0), "zero address");
        require(attestationHash != bytes32(0), "missing attestation");
        require(unit <= 1, "unit");
        require(floorPrice > 0 && floorPrice <= type(uint128).max / 16, "floor");
        require(target > 0 && target <= type(uint128).max / 2, "target");
        require(runExpires > block.timestamp, "run expired");
        nodes[node] = Node(
            operator,
            receiptSigner,
            attestationHash,
            unit,
            floorPrice,
            target,
            floorPrice,
            0,
            uint64(block.timestamp / EPOCH_SECONDS),
            runExpires
        );
        emit NodeRegistered(node, operator, receiptSigner, attestationHash, unit, floorPrice, target, runExpires);
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
        require(amount > 0 && amount <= (unit == 0 ? MAX_BYTES : MAX_SECONDS), "amount");
        require(buyerKey != bytes32(0), "buyer key");
        require(block.timestamp < n.runExpires, "run expired");
        require(msg.value == uint256(amount) * n.price, "exact price");
        uint64 boughtAt = uint64(block.timestamp);
        uint64 expires = boughtAt + PURCHASE_SECONDS;
        if (expires > n.runExpires) expires = n.runExpires;
        id = nextPurchaseId++;
        purchases[id] = PurchaseData(
            node,
            msg.sender,
            buyerKey,
            n.operator,
            n.receiptSigner,
            unit,
            amount,
            n.price,
            n.floorPrice,
            boughtAt,
            expires,
            0,
            0,
            boughtAt,
            false
        );
        uint256 booked = uint256(n.booked) + amount;
        uint256 capacity = uint256(n.target) * 2;
        n.booked = uint128(booked > capacity ? capacity : booked);
        emit Purchase(id, node, msg.sender, buyerKey, unit, amount, n.price, expires);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("DsmackUsageEscrow"), keccak256("1"), block.chainid, address(this))
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

    function settle(Receipt[] calldata receipts, bytes[] calldata signatures) external {
        require(receipts.length == signatures.length && receipts.length > 0, "receipt lengths");
        for (uint256 i; i < receipts.length; ++i) {
            _settle(receipts[i], signatures[i]);
        }
    }

    function _settle(Receipt calldata r, bytes calldata signature) private {
        PurchaseData storage p = purchases[r.purchaseId];
        require(p.payer != address(0) && !p.closed, "purchase closed or unknown");
        require(block.timestamp < uint256(p.expires) + SETTLEMENT_GRACE, "settlement expired");
        require(r.sequence > p.sequence && r.used >= p.used && r.used <= p.amount, "usage or sequence");
        require(r.endedAt >= p.endedAt && r.endedAt <= p.expires && r.endedAt <= block.timestamp, "receipt time");
        require(signature.length == 65, "signature length");
        bytes32 sigR;
        bytes32 sigS;
        uint8 sigV;
        assembly ("memory-safe") {
            sigR := calldataload(signature.offset)
            sigS := calldataload(add(signature.offset, 32))
            sigV := byte(0, calldataload(add(signature.offset, 64)))
        }
        require(uint256(sigS) <= HALF_ORDER && (sigV == 27 || sigV == 28), "signature canonical");
        require(ecrecover(receiptDigest(r), sigV, sigR, sigS) == p.receiptSigner, "receipt signer");
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
