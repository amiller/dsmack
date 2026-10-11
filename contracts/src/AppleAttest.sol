// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {P384} from "./P384.sol";
import {AppleLeaf} from "./AppleLeaf.sol";
import {AppleAuthData} from "./AppleAuthData.sol";

/// Direct certificate/assertion verification against the fixed Apple App
/// Attestation CA 1 key, whose root endorsement is in the deployment manifest.
/// Supported profiles: macOS 27 and iOS 27, P256 keys, SHA256 CDHash, exact
/// per-platform key ACL (leaf OID 1.2.840.113635.100.8.6) pinned at deployment.
/// Subclasses decide which (CDHash, RP ID hash) pairs are admitted.
abstract contract AppleAttest {
    address public immutable registry;
    bytes16 public immutable aaguid;
    uint32 public immutable validationCategory;
    bytes32 public immutable keyACL;
    bytes32 constant MAC_ACL=keccak256(hex"3046a344044230400c023131303a30090c026f6ba1030101ff30090c026f61a1030101ff300b0c046f64656ca1030101ff30150c046f73676ea0060c04727365633005a603020101");
    bytes32 constant IOS_ACL=keccak256(hex"3049a347044530430c023131303d300a0c036f6b64a1030101ff30090c026f61a1030101ff300b0c046f73676ea1030101ff300b0c046f64656ca1030101ff300a0c036f636ba1030101ff");
    struct Key {uint256 x;uint256 y;uint64 expires;uint32 counter;bool enrolled;}
    mapping(bytes32=>Key) public keys;
    /// Latest successfully verified assertion, for downstream receipt checks.
    /// Enrollment alone does not populate this record. Consumers must bind the
    /// exact context to their action and enforce their own replay/expiry policy.
    struct AssertionEvidence {bytes32 context;bytes32 cdhash;bytes32 rp;uint64 checkedAt;uint32 counter;}
    mapping(bytes32=>AssertionEvidence) public assertionEvidence;
    event Enrolled(bytes32 indexed keyId,uint64 expires);
    event Asserted(bytes32 indexed keyId,uint32 counter,bytes32 context);
    constructor(address registry_,bytes16 aaguid_,uint32 category_,bool ios_){
        require(registry_!=address(0),"empty policy");
        registry=registry_;aaguid=aaguid_;validationCategory=category_;keyACL=ios_?IOS_ACL:MAC_ACL;
    }
    function admit(bytes32 cdhash,bytes32 rp) internal view virtual;
    function enroll(bytes calldata cert,bytes calldata auth,bytes calldata clientData) external returns(bytes32 kid){
        require(clientData.length<=2048 && block.timestamp<=1899590400,"anchor expiry/client data");
        AppleLeaf.Parsed memory leaf=AppleLeaf.parse(cert,0x7d3811d00e402fdff4a937cc5cadf0ad852fb779bdcacb69f996cb599c1c61dd,sha256(abi.encodePacked(auth,sha256(clientData))),keyACL);
        bytes32 cdhash;bytes32 rp;(,kid,cdhash,rp)=AppleAuthData.check(auth,aaguid,true,leaf.x,leaf.y,validationCategory);admit(cdhash,rp);
        require(!keys[kid].enrolled,"already enrolled");
        require(P384.verify(
            0xae5b37a0774d79b2358f40e7d1f22626,
            0xf1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706,
            0x9e98d363bd5e370fbfa08e329e8073a9,
            0x85e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99,
            uint256(leaf.tbsHash),leaf.rhi,leaf.rlo,leaf.shi,leaf.slo),"Apple certificate signature");
        keys[kid]=Key(leaf.x,leaf.y,leaf.expires,0,true);emit Enrolled(kid,leaf.expires);
    }
    /// proof = abi.encode(keyId, rawAuthenticatorData, signatureR, signatureS).
    /// Expected context is the clientDataHash the app passed to generateAssertion.
    function verify(bytes32 context,bytes calldata proof) external returns(bytes32 kid){
        require(msg.sender==registry,"registry only");
        bytes memory auth;uint256 r;uint256 s;(kid,auth,r,s)=abi.decode(proof,(bytes32,bytes,uint256,uint256));
        Key storage k=keys[kid];require(k.enrolled && block.timestamp<=k.expires && block.timestamp<=1899590400,"key validity");
        (uint32 count,,bytes32 cdhash,bytes32 rp)=AppleAuthData.check(auth,aaguid,false,0,0,validationCategory);admit(cdhash,rp);
        require(count>k.counter,"assertion replay");
        bytes32 digest=sha256(abi.encodePacked(sha256(abi.encodePacked(auth,context))));
        (bool ok,bytes memory result)=address(0x100).staticcall(abi.encode(digest,r,s,k.x,k.y));
        require(ok && result.length==32 && abi.decode(result,(uint256))==1,"assertion signature");
        k.counter=count;
        assertionEvidence[kid]=AssertionEvidence(context,cdhash,rp,uint64(block.timestamp),count);
        emit Asserted(kid,count,context);
    }
}
