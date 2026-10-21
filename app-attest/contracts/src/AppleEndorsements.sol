// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleIntermediate} from "./AppleIntermediate.sol";
import {P384} from "./P384.sol";

contract AppleEndorsements {
    struct Intermediate {bytes32 subject;P384.C384Elm key;uint64 notBefore;uint64 notAfter;}
    mapping(bytes32=>Intermediate) public intermediates;
    event IntermediateEndorsed(bytes32 indexed id,uint64 notBefore,uint64 notAfter);
    function endorseIntermediate(bytes calldata der) external returns(bytes32 id){
        AppleIntermediate.Parsed memory ca=AppleIntermediate.parse(der);
        uint256 hh;uint256 hl;bytes memory digest=ca.digest;
        assembly{hh:=shr(128,mload(add(digest,32))) hl:=mload(add(digest,48))}
        require(P384.verify384(_rootKey(),hh,hl,ca.rhi,ca.rlo,ca.shi,ca.slo),"root certificate signature");
        id=entryId(ca.subject,ca.key);
        require(intermediates[id].notAfter==0,"already endorsed");
        intermediates[id]=Intermediate(ca.subject,ca.key,ca.notBefore,ca.expires);
        emit IntermediateEndorsed(id,ca.notBefore,ca.expires);
    }
    function entryId(bytes32 subject,P384.C384Elm memory key) public pure returns(bytes32){return sha256(abi.encode(subject,key));}
    function get(bytes32 id) external view returns(Intermediate memory){return intermediates[id];}
    // trust/apple-app-attestation-root.pem, uncompressed secp384r1 public key.
    function _rootKey() internal pure virtual returns(P384.C384Elm memory){
        return P384.C384Elm(0x4531e198b5b4ec04da1502045704ed4f,0x877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd6,0x56141404702831e43f70b88fd6c394b6,0x08ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35);
    }
}
