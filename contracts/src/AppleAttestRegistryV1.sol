// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {AppleAttest} from "attest/AppleAttest.sol";
import {CDRegistry} from "./CDRegistry.sol";

/// Admits any CDHash the CDRegistry admits, under the RP ID it recorded for that CodeDirectory.
contract AppleAttestRegistryV1 is AppleAttest {
    CDRegistry public immutable cds;
    constructor(AppleEndorsements endorsements_,address registry_,CDRegistry cds_,bytes16 aaguid_,uint32 category_,bool ios_) AppleAttest(endorsements_,registry_,aaguid_,category_,ios_){cds=cds_;}
    function admit(bytes32 cdhash,bytes32 rp) internal view override{require(rp!=0 && cds.rpIdHash(cdhash)==rp,"build not admitted");}
}
