// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "./AppleEndorsements.sol";
import {AppleAttest} from "./AppleAttest.sol";

interface IAppleAttestVerifier {
    function verify(bytes calldata proof,bytes32[] calldata inputs) external view returns(bool);
}

abstract contract AppleAttestZK is AppleAttest {
    IAppleAttestVerifier public immutable leafVerifier;
    bytes32 public immutable keyACLSHA256;
    struct PublicValues {
        bytes32 rpIdHash;bytes32 cdhash;bytes32 clientDataHash;
        uint256 x;uint256 y;uint64 notBefore;uint64 notAfter;
        bytes16 aaguid;uint32 validationCategory;bytes32 keyACLHash;
    }
    constructor(AppleEndorsements endorsements_,address registry_,bytes16 aaguid_,uint32 category_,bool ios_,IAppleAttestVerifier leafVerifier_)
        AppleAttest(endorsements_,registry_,aaguid_,category_,ios_){
        require(address(leafVerifier_).code.length!=0,"empty leaf verifier");leafVerifier=leafVerifier_;
        keyACLSHA256=ios_?sha256(hex"3049a347044530430c023131303d300a0c036f6b64a1030101ff30090c026f61a1030101ff300b0c046f73676ea1030101ff300b0c046f64656ca1030101ff300a0c036f636ba1030101ff"):
            sha256(hex"3046a344044230400c023131303a30090c026f6ba1030101ff30090c026f61a1030101ff300b0c046f64656ca1030101ff30150c046f73676ea0060c04727365633005a603020101");
    }
    function enrollLeafProof(bytes calldata proof,bytes calldata clientData,PublicValues calldata p,uint128[6] calldata key,bytes32 id) external returns(bytes32 kid){
        require(clientData.length<=2048 && block.timestamp<=ROOT_NOT_AFTER,"anchor expiry/client data");
        AppleEndorsements.Intermediate memory ca=endorsements.get(id);
        require(ca.notAfter!=0 && ca.notBefore<=block.timestamp && block.timestamp<=ca.notAfter,"intermediate validity");
        require(ca.key.xhi==key[0] && ca.key.xlo==(uint256(key[1])<<128|key[2]) &&
            ca.key.yhi==key[3] && ca.key.ylo==(uint256(key[4])<<128|key[5]),"intermediate key");
        bytes32[] memory inputs; (kid,inputs)=_proofInputs(clientData,p,24);
        for(uint256 i;i<6;i++)inputs[16+i]=bytes32(uint256(key[i]));_split(inputs,22,uint256(ca.subject));
        require(leafVerifier.verify(proof,inputs),"attestation proof");
        _storeKey(kid,p.x,p.y,p.notAfter<ca.notAfter?p.notAfter:ca.notAfter);
    }
    function _proofInputs(bytes calldata clientData,PublicValues calldata p,uint256 size) private view returns(bytes32 kid,bytes32[] memory inputs){
        require(sha256(clientData)==p.clientDataHash,"client data hash");
        require(p.aaguid==aaguid,"aaguid");require(p.validationCategory==validationCategory,"validation category");
        require(p.keyACLHash==keyACLSHA256,"key ACL");
        require(p.notBefore<=block.timestamp && block.timestamp<=p.notAfter,"certificate validity");
        kid=sha256(abi.encodePacked(bytes1(0x04),p.x,p.y));admit(p.cdhash,p.rpIdHash);_checkNewKey(kid);
        inputs=new bytes32[](size);
        _split(inputs,0,uint256(p.rpIdHash));_split(inputs,2,uint256(p.cdhash));_split(inputs,4,uint256(p.clientDataHash));
        _split(inputs,6,p.x);_split(inputs,8,p.y);
        inputs[10]=bytes32(uint256(p.notBefore));inputs[11]=bytes32(uint256(p.notAfter));
        inputs[12]=bytes32(uint256(uint128(p.aaguid)));inputs[13]=bytes32(uint256(p.validationCategory));
        _split(inputs,14,uint256(p.keyACLHash));
    }
    function _split(bytes32[] memory inputs,uint256 i,uint256 value) private pure {
        inputs[i]=bytes32(value>>128);inputs[i+1]=bytes32(uint256(uint128(value)));
    }
}
