// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/security/ReentrancyGuard.sol";
import {IAdmissionV1} from "./IAdmissionV1.sol";
import {DemoTokenV1, MembershipReceiptV1} from "./DemoAssetsV1.sol";

/// Contract integration candidate. Every action requires fresh policy-specific
/// evidence. No permit signer, cached-membership authorization, or plaintext mailbox.
contract DemoV1 is ReentrancyGuard {
    enum Action { Join, Claim, Bootstrap, Receipt }
    struct Category {
        address adapter;
        bytes32 adapterCodeHash;
        bytes32 family;
        bytes32 policy;
        bool overallEligible;
        bool enabled;
    }
    struct Request {
        Action action;
        bytes32 category;
        address owner;
        address memberSigner;
        bytes32 sessionKeyHash;
        uint256 nonce;
        uint64 validUntil;
        bytes32 scope; // zero = overall; otherwise category id
        uint256 keyX;
        uint256 keyY;
        bytes32 envelopeDigest;
    }
    struct Member { address owner; bytes32 category; uint64 lastChecked; bool revoked; }
    struct SharedKey { uint256 x; uint256 y; bytes32 bootstrapMember; bool committed; }
    address public immutable owner;
    DemoTokenV1 public immutable token;
    MembershipReceiptV1 public immutable receipt;
    bool public paused = true;
    mapping(bytes32 => Category) public categories;
    mapping(bytes32 => Member) public members;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public claimed;
    mapping(bytes32 => SharedKey) public sharedKeys;
    uint256 public claimCount;
    event CategoryAdded(bytes32 indexed category, bytes32 family, bytes32 policy, address adapter, bytes32 codeHash, bool overallEligible);
    event CategoryEnabled(bytes32 indexed category, bool enabled);
    event Paused(bool paused);
    event Revoked(bytes32 indexed member);
    event Checked(bytes32 indexed member, bytes32 indexed category, address indexed owner, bytes32 context, bytes32 sessionKeyHash);
    event Claimed(bytes32 indexed member, address indexed recipient);
    event Bootstrapped(bytes32 indexed scope, bytes32 indexed member, uint256 x, uint256 y);
    event KeyReceipt(bytes32 indexed scope, bytes32 indexed member, bytes32 envelopeDigest, bytes32 context);
    error Unauthorized();
    error InvalidRequest();
    error Inactive();
    error InvalidProof();
    modifier onlyOwner() { if (msg.sender != owner) revert Unauthorized(); _; }
    constructor(address admin) {
        if (admin == address(0)) revert InvalidRequest();
        owner = admin;
        token = new DemoTokenV1();
        receipt = new MembershipReceiptV1();
    }
    function addCategory(bytes32 family, bytes32 policy, address adapter, bool overallEligible) external onlyOwner returns (bytes32 id) {
        if (family == 0 || policy == 0 || adapter.code.length == 0) revert InvalidRequest();
        id = keccak256(abi.encode(uint256(1), family, policy));
        if (categories[id].adapter != address(0)) revert InvalidRequest();
        // Adapter must have immutable semantics; proxies are outside this policy.
        categories[id] = Category(adapter, adapter.codehash, family, policy, overallEligible, false);
        emit CategoryAdded(id, family, policy, adapter, adapter.codehash, overallEligible);
    }
    function setCategoryEnabled(bytes32 id, bool enabled) external onlyOwner {
        if (categories[id].adapter == address(0)) revert InvalidRequest();
        categories[id].enabled = enabled;
        emit CategoryEnabled(id, enabled);
    }
    function setPaused(bool value) external onlyOwner { paused = value; emit Paused(value); }
    function revoke(bytes32 id) external onlyOwner { members[id].revoked = true; emit Revoked(id); }
    function isActive(bytes32 id) external view returns (bool) {
        Member memory m = members[id];
        Category memory c = categories[m.category];
        return !paused && m.owner != address(0) && !m.revoked && c.enabled
            && c.adapter.codehash == c.adapterCodeHash && block.timestamp < uint256(m.lastChecked) + 60;
    }
    function contextHash(Request calldata r) public view virtual returns (bytes32) {
        return keccak256(abi.encode("TEE_INTEROP_DEMO_V1", block.chainid, address(this), r));
    }
    function execute(Request calldata r, bytes calldata proof, bytes calldata memberSignature, bytes calldata groupSignature)
        external nonReentrant returns (bytes32 id)
    {
        Category memory c = categories[r.category];
        if (paused || !c.enabled || c.adapter.code.length == 0 || c.adapter.codehash != c.adapterCodeHash) revert Inactive();
        if (msg.sender != r.owner || r.memberSigner == address(0)) revert Unauthorized();
        if (r.nonce != nonces[r.owner] || r.validUntil <= block.timestamp || r.validUntil > block.timestamp + 60
            || r.sessionKeyHash == 0 || proof.length > 32768) revert InvalidRequest();
        bytes32 digest = contextHash(r);
        if (ECDSA.recover(ECDSA.toEthSignedMessageHash(digest), memberSignature) != r.memberSigner) revert InvalidProof();
        nonces[r.owner]++;
        bytes32 subject = IAdmissionV1(c.adapter).verify(digest, proof);
        if (subject == 0) revert InvalidProof();
        id = keccak256(abi.encode(r.category, subject));
        Member storage m = members[id];
        if (m.revoked || (m.owner != address(0) && m.owner != r.owner)) revert Unauthorized();
        m.owner = r.owner;
        m.category = r.category;
        m.lastChecked = uint64(block.timestamp);
        emit Checked(id, r.category, r.owner, digest, r.sessionKeyHash);
        if (r.action == Action.Join || r.action == Action.Claim) {
            if (r.scope != 0 || r.keyX != 0 || r.keyY != 0 || r.envelopeDigest != 0 || groupSignature.length != 0) revert InvalidRequest();
            if (r.action == Action.Claim) {
                if (claimed[id]) revert InvalidRequest();
                claimed[id] = true;
                claimCount++;
                receipt.mint(r.owner, uint256(id), r.category);
                require(token.transfer(r.owner, 1 ether), "transfer failed");
                emit Claimed(id, r.owner);
            }
        } else {
            if (r.scope == 0 ? !c.overallEligible : r.scope != r.category) revert Unauthorized();
            SharedKey storage k = sharedKeys[r.scope];
            if (r.action == Action.Bootstrap) {
                if (k.committed || r.envelopeDigest != 0) revert InvalidRequest();
                _groupProof(digest, r.keyX, r.keyY, groupSignature);
                k.x = r.keyX; k.y = r.keyY; k.bootstrapMember = id; k.committed = true;
                emit Bootstrapped(r.scope, id, r.keyX, r.keyY);
            } else {
                if (!k.committed || r.keyX != k.x || r.keyY != k.y || r.envelopeDigest == 0) revert InvalidRequest();
                _groupProof(digest, k.x, k.y, groupSignature);
                emit KeyReceipt(r.scope, id, r.envelopeDigest, digest);
            }
        }
    }
    function _groupProof(bytes32 digest, uint256 x, uint256 y, bytes calldata signature) internal view {
        if (signature.length != 64) revert InvalidProof();
        (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
        // Native RIP-7212. Missing precompile and malformed return fail closed.
        (bool ok, bytes memory result) = address(0x100).staticcall(abi.encode(digest, r, s, x, y));
        if (!ok || result.length != 32 || abi.decode(result, (uint256)) != 1) revert InvalidProof();
    }
}
