// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "./AppleEndorsements.sol";
import {AppleAttestZK,IAppleAttestVerifier} from "./AppleAttestZK.sol";

/// One approved build: fixed App ID hash and CDHash.
contract MacAppAttestZKV1 is AppleAttestZK {
    bytes32 public immutable appHash;
    bytes32 public immutable approvedCDHash;
    constructor(AppleEndorsements endorsements_,address registry_,bytes32 appHash_,bytes32 cdhash_,bytes16 aaguid_,uint32 category_,bool ios_,IAppleAttestVerifier leafVerifier_) AppleAttestZK(endorsements_,registry_,aaguid_,category_,ios_,leafVerifier_){
        require(appHash_!=0 && cdhash_!=0,"empty policy");appHash=appHash_;approvedCDHash=cdhash_;
    }
    function admit(bytes32 cdhash,bytes32 rp) internal view override{require(rp==appHash,"app identity");require(cdhash==approvedCDHash,"current CDHash");}
}
