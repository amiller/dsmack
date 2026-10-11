// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {ResearchBadges} from "./ResearchBadges.sol";
import {DemoV1} from "./DemoV1.sol";

/// A narrow ERC-1271 account for research badges, not a general-purpose wallet.
/// No owner/admin/sponsor recovery path; a handoff requires both old and new keys.
contract PersonalBadgeAccount {
    address public immutable badges;
    uint256 public keyX;
    uint256 public keyY;
    uint256 public generation;
    bytes32 public constant CONSENT_DOMAIN = keccak256("ATTEST_PERSONAL_CONSENT_V1");
    bytes32 public constant HANDOFF_DOMAIN = keccak256("ATTEST_PERSONAL_HANDOFF_V1");
    uint256 constant P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 constant B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
    event ControlTransferred(uint256 indexed generation,uint256 keyX,uint256 keyY);

    constructor(address badges_,uint256 x,uint256 y) {
        require(badges_.code.length != 0 && validPoint(x,y),"account policy/key");
        badges=badges_;keyX=x;keyY=y;
    }
    function validPoint(uint256 x,uint256 y) public pure returns(bool) {
        return x < P && y < P && (x != 0 || y != 0)
            && mulmod(y,y,P) == addmod(addmod(mulmod(mulmod(x,x,P),x,P),P-mulmod(3,x,P),P),B,P);
    }
    function consentDigest(bytes32 claim) public view returns(bytes32) {
        return sha256(abi.encode(CONSENT_DOMAIN,block.chainid,address(this),generation,claim));
    }
    function handoffDigest(uint256 x,uint256 y,uint64 deadline) public view returns(bytes32) {
        return sha256(abi.encode(HANDOFF_DOMAIN,block.chainid,address(this),generation,x,y,deadline));
    }
    function verifies(bytes32 digest,uint256 x,uint256 y,bytes calldata signature) internal view returns(bool) {
        if(signature.length != 64) return false;
        (bytes32 r,bytes32 s)=abi.decode(signature,(bytes32,bytes32));
        (bool ok,bytes memory result)=address(0x100).staticcall(abi.encode(digest,r,s,x,y));
        return ok && result.length == 32 && abi.decode(result,(uint256)) == 1;
    }
    function isValidSignature(bytes32 claim,bytes calldata signature) external view returns(bytes4) {
        return msg.sender == badges && verifies(consentDigest(claim),keyX,keyY,signature)
            ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
    function handoff(uint256 x,uint256 y,uint64 deadline,bytes calldata oldSignature,bytes calldata newSignature) external {
        require(deadline >= block.timestamp && deadline <= block.timestamp + 3600,"handoff expiry");
        require(validPoint(x,y) && (x != keyX || y != keyY),"new key");
        bytes32 digest=handoffDigest(x,y,deadline);
        require(verifies(digest,keyX,keyY,oldSignature),"current key consent");
        require(verifies(digest,x,y,newSignature),"new key possession");
        keyX=x;keyY=y;generation++;
        emit ControlTransferred(generation,x,y);
    }
}

/// Anyone can deploy an account, but its deterministic address and control key
/// cannot be redirected by the sponsor or by front-running the deployment.
contract PersonalBadgeAccountFactory {
    address public immutable badges;
    mapping(address => bool) public isAccount;
    event AccountCreated(address indexed account,uint256 x,uint256 y);
    constructor(address badges_) {require(badges_.code.length != 0,"badges");badges=badges_;}
    function accountAddress(uint256 x,uint256 y) public view returns(address) {
        bytes32 salt=keccak256(abi.encode(x,y));
        bytes32 initHash=keccak256(abi.encodePacked(type(PersonalBadgeAccount).creationCode,abi.encode(badges,x,y)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff),address(this),salt,initHash)))));
    }
    /// Sponsor-facing path: creation is bound to a fresh admitted key receipt.
    /// The unrestricted create() remains safe for callers paying their own gas.
    function creationDigest(uint256 x,uint256 y,bytes32 kid) public view returns(bytes32) {
        return keccak256(abi.encode(keccak256("ATTEST_PERSONAL_CREATE_V1"),block.chainid,address(this),kid,x,y));
    }
    function createForMember(uint256 x,uint256 y,bytes32 kid,DemoV1.Request calldata request) external returns(PersonalBadgeAccount) {
        ResearchBadges policy=ResearchBadges(badges);
        require(request.action == DemoV1.Action.Receipt && request.category == policy.category()
            && request.envelopeDigest == creationDigest(x,y,kid),"creation binding");
        require(request.validUntil > block.timestamp,"creation expiry");
        (bytes32 context,bytes32 cdhash,bytes32 rp,uint64 checkedAt,)=policy.adapter().assertionEvidence(kid);
        require(context != 0 && context == policy.network().contextHash(request)
            && checkedAt <= block.timestamp && block.timestamp < uint256(checkedAt)+60,"creation evidence");
        require(rp != 0 && policy.adapter().cds().rpIdHash(cdhash) == rp,"admitted build");
        require(policy.network().isActive(keccak256(abi.encode(policy.category(),kid))),"inactive member");
        return create(x,y);
    }
    function create(uint256 x,uint256 y) public returns(PersonalBadgeAccount account) {
        address predicted=accountAddress(x,y);
        if(predicted.code.length != 0) return PersonalBadgeAccount(predicted);
        account=new PersonalBadgeAccount{salt:keccak256(abi.encode(x,y))}(badges,x,y);
        isAccount[address(account)]=true;
        emit AccountCreated(address(account),x,y);
    }
}
