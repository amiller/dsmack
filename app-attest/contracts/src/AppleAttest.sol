// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "./AppleEndorsements.sol";
import {P384} from "./P384.sol";
import {AppleLeaf} from "./AppleLeaf.sol";
import {AppleAuthData} from "./AppleAuthData.sol";

/// Direct certificate/assertion verification with root-endorsed intermediates.
/// Supported profiles: macOS 27 and iOS 27, P256 keys, SHA256 CDHash, exact
/// per-platform key ACL (leaf OID 1.2.840.113635.100.8.6) pinned at deployment.
/// Subclasses decide which (CDHash, RP ID hash) pairs are admitted.
abstract contract AppleAttest {
    AppleEndorsements public immutable endorsements;
    // openssl x509 -in trust/apple-app-attestation-root.pem -noout -enddate: 2045-03-15 UTC.
    uint64 public constant ROOT_NOT_AFTER=2373148800;
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
    constructor(AppleEndorsements endorsements_,address registry_,bytes16 aaguid_,uint32 category_,bool ios_){
        require(registry_!=address(0),"empty policy");
        require(address(endorsements_).code.length!=0,"empty endorsements");endorsements=endorsements_;
        registry=registry_;aaguid=aaguid_;validationCategory=category_;keyACL=ios_?IOS_ACL:MAC_ACL;
    }
    function admit(bytes32 cdhash,bytes32 rp) internal view virtual;
    function enroll(bytes calldata cert,bytes calldata auth,bytes calldata clientData,bytes32 id) external returns(bytes32 kid){
        require(clientData.length<=2048 && block.timestamp<=ROOT_NOT_AFTER,"anchor expiry/client data");
        AppleEndorsements.Intermediate memory ca=endorsements.get(id);
        require(ca.notAfter!=0 && block.timestamp>=ca.notBefore && block.timestamp<=ca.notAfter,"intermediate validity");
        AppleLeaf.Parsed memory leaf=AppleLeaf.parse(cert,ca.subject,sha256(abi.encodePacked(auth,sha256(clientData))),keyACL);
        bytes32 cdhash;bytes32 rp;(,kid,cdhash,rp)=AppleAuthData.check(auth,aaguid,true,leaf.x,leaf.y,validationCategory);admit(cdhash,rp);
        _checkNewKey(kid);
        require(P384.verify(
            ca.key.xhi,ca.key.xlo,ca.key.yhi,ca.key.ylo,
            uint256(leaf.tbsHash),leaf.rhi,leaf.rlo,leaf.shi,leaf.slo),"Apple certificate signature");
        _storeKey(kid,leaf.x,leaf.y,leaf.expires<ca.notAfter?leaf.expires:ca.notAfter);
    }
    function _checkNewKey(bytes32 kid) internal view {require(!keys[kid].enrolled,"already enrolled");}
    function _storeKey(bytes32 kid,uint256 x,uint256 y,uint64 expires) internal {
        keys[kid]=Key(x,y,expires,0,true);emit Enrolled(kid,expires);
    }
    /// proof = abi.encode(keyId, rawAuthenticatorData, signatureR, signatureS).
    /// Expected context is the clientDataHash the app passed to generateAssertion.
    function verify(bytes32 context,bytes calldata proof) external returns(bytes32 kid){
        require(msg.sender==registry,"registry only");
        bytes memory auth;uint256 r;uint256 s;(kid,auth,r,s)=abi.decode(proof,(bytes32,bytes,uint256,uint256));
        Key storage k=keys[kid];require(k.enrolled && block.timestamp<=k.expires && block.timestamp<=ROOT_NOT_AFTER,"key validity");
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
