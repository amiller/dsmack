// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {ERC721} from "openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/security/ReentrancyGuard.sol";
import {DemoV2} from "./DemoV2.sol";
import {DemoV1} from "./DemoV1.sol";
import {AppleAttestRegistryV1} from "../AppleAttestRegistryV1.sol";

/// Non-transferable research receipts. A sponsored network Receipt must bind
/// envelopeDigest to claimDigest, and the personal recipient must consent.
/// Not a unique-device/person registry. Requires the evidence-enabled adapter.
contract ResearchBadges is ERC721, ReentrancyGuard {
    DemoV2 public immutable network;
    AppleAttestRegistryV1 public immutable adapter;
    bytes32 public immutable category;
    bytes32 public immutable publisherTeam;
    struct Claim {address recipient;bytes32 keyId;uint8 level;uint256 parent;uint64 deadline;}
    struct Badge {bytes32 member;bytes32 team;uint8 level;uint256 parent;}
    mapping(uint256 => Badge) public badges;
    mapping(bytes32 => bool) public participantClaimed;
    mapping(bytes32 => bool) public builderTeamClaimed;
    mapping(uint256 => bool) public upgraded;
    mapping(address => uint256) public participantOf;
    mapping(uint256 => uint256) public builderOf;
    uint256 public nextId = 1;
    event BadgeClaimed(uint256 indexed tokenId,address indexed recipient,uint8 level,bytes32 member,bytes32 team,uint256 parent);

    constructor(DemoV2 network_, AppleAttestRegistryV1 adapter_, bytes32 category_, bytes32 publisherTeam_)
        ERC721("Attest Testnet Research Badges", "ATTEST")
    {
        require(address(network_) != address(0) && address(adapter_) != address(0) && publisherTeam_ != 0, "policy");
        (address configured,,,,,) = network_.categories(category_);
        require(configured == address(adapter_) && adapter_.registry() == address(network_), "adapter");
        network = network_;adapter = adapter_;category = category_;publisherTeam = publisherTeam_;
    }
    /// A generic copy signed by another team cannot claim for arbitrary users.
    /// The team must sign an explicit app identity bound to this NFT account.
    function builderBundleId(address recipient) public pure returns(string memory) {
        return string(abi.encodePacked("dev.attestnode.builder.a",Strings.toHexString(uint160(recipient),20)));
    }
    function claimDigest(Claim calldata c) public view returns(bytes32) {
        return keccak256(abi.encode("ATTEST_RESEARCH_BADGE_V1",block.chainid,address(this),c));
    }
    function claim(Claim calldata c, DemoV1.Request calldata request, bytes calldata recipientSignature)
        external nonReentrant returns(uint256 tokenId)
    {
        require(c.recipient != address(0) && c.deadline >= block.timestamp && c.deadline <= block.timestamp + 300, "claim expiry");
        require(c.level == 1 || c.level == 2, "level");
        bytes32 digest = claimDigest(c);
        require(recipientConsents(c.recipient,digest,recipientSignature), "recipient consent");
        require(request.action == DemoV1.Action.Receipt && request.category == category && request.envelopeDigest == digest, "receipt binding");
        require(request.validUntil > block.timestamp, "receipt expiry");
        (bytes32 context, bytes32 cdhash, bytes32 rp, uint64 checkedAt,) = adapter.assertionEvidence(c.keyId);
        require(context != 0 && context == network.contextHash(request) && checkedAt <= block.timestamp && block.timestamp < uint256(checkedAt) + 60, "assertion evidence");
        require(rp != 0 && adapter.cds().rpIdHash(cdhash) == rp, "admitted build");
        bytes32 member = keccak256(abi.encode(category,c.keyId));
        require(network.isActive(member), "inactive member");
        bytes32 team = adapter.cds().teamIdHash(cdhash);
        if(c.level == 1) {
            require(c.parent == 0 && !participantClaimed[member], "participant already claimed/parent");
            participantClaimed[member] = true;
        } else {
            require(team != 0 && team != publisherTeam && !builderTeamClaimed[team], "independent team");
            require(adapter.cds().bundleIdHash(cdhash) == sha256(bytes(builderBundleId(c.recipient))), "recipient-bound build");
            require(ownerOf(c.parent) == c.recipient && badges[c.parent].level == 1 && !upgraded[c.parent], "parent");
            builderTeamClaimed[team] = true;upgraded[c.parent] = true;
        }
        tokenId = nextId++;
        badges[tokenId] = Badge(member,team,c.level,c.parent);
        // Consent is checked above. No receiver callback or arbitrary external
        // code runs during mint, and no private key is held by the gas sponsor.
        _mint(c.recipient,tokenId);
        if(c.level == 1 && participantOf[c.recipient] == 0) participantOf[c.recipient] = tokenId;
        if(c.level == 2) builderOf[c.parent] = tokenId;
        emit BadgeClaimed(tokenId,c.recipient,c.level,member,team,c.parent);
    }
    function tokenURI(uint256 tokenId) public view override returns(string memory) {
        _requireMinted(tokenId);
        Badge memory b=badges[tokenId];
        return string(abi.encodePacked('data:application/json;utf8,{"name":"Attest ',b.level == 1 ? "Participant" : "Independent Builder",'","description":"Historical testnet receipt. Not unique-device or unique-person identity. No monetary value.","level":',Strings.toString(b.level),',"parent":',Strings.toString(b.parent),',"member":"',Strings.toHexString(uint256(b.member),32),'","teamHash":"',Strings.toHexString(uint256(b.team),32),'"}'));
    }
    function recipientConsents(address recipient,bytes32 digest,bytes calldata signature) internal view returns(bool) {
        if(recipient.code.length == 0) {
            (address recovered,ECDSA.RecoverError error)=ECDSA.tryRecover(digest,signature);
            return error == ECDSA.RecoverError.NoError && recovered == recipient;
        }
        (bool ok,bytes memory result)=recipient.staticcall(abi.encodeWithSelector(bytes4(0x1626ba7e),digest,signature));
        return ok && result.length >= 32 && abi.decode(result,(bytes32)) == bytes32(bytes4(0x1626ba7e));
    }
    function approve(address,uint256) public pure override {revert("non-transferable");}
    function setApprovalForAll(address,bool) public pure override {revert("non-transferable");}
    function _beforeTokenTransfer(address from,address to,uint256 firstId,uint256 batchSize) internal override {
        require(from == address(0),"non-transferable");super._beforeTokenTransfer(from,to,firstId,batchSize);
    }
}
