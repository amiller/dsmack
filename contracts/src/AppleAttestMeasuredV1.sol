// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleAttest} from "./AppleAttest.sol";
import {MeasurementRegistry} from "./MeasurementRegistry.sol";

/// Admits a CDHash while its registered measurement's window is open, under the RP ID sealed in it.
contract AppleAttestMeasuredV1 is AppleAttest {
    MeasurementRegistry public immutable cds;
    constructor(address registry_,MeasurementRegistry cds_,bytes16 aaguid_,uint32 category_,bool ios_) AppleAttest(registry_,aaguid_,category_,ios_){cds=cds_;}
    function admit(bytes32 cdhash,bytes32 rp) internal view override{require(rp!=0 && cds.rpIdHash(cdhash)==rp,"build not admitted");}
}
