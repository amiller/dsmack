// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleAttest} from "./AppleAttest.sol";

/// One approved build: fixed App ID hash and CDHash.
contract MacAppAttestV1 is AppleAttest {
    bytes32 public immutable appHash;
    bytes32 public immutable approvedCDHash;
    constructor(address registry_,bytes32 appHash_,bytes32 cdhash_,bytes16 aaguid_,uint32 category_,bool ios_) AppleAttest(registry_,aaguid_,category_,ios_){
        require(appHash_!=0 && cdhash_!=0,"empty policy");appHash=appHash_;approvedCDHash=cdhash_;
    }
    function admit(bytes32 cdhash,bytes32 rp) internal view override{require(rp==appHash,"app identity");require(cdhash==approvedCDHash,"current CDHash");}
}
