// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {CDRegistry} from "./CDRegistry.sol";
import {AppleAttestRegistryV1} from "./AppleAttestRegistryV1.sol";

/// Preserve Apple-verified keys when replacing an immutable Mac registry.
contract AppleAttestRegistryMigrationV1 is AppleAttestRegistryV1 {
    AppleAttestRegistryV1 public immutable previous;
    constructor(AppleEndorsements endorsements_,address registry_,CDRegistry cds_,bytes16 aaguid_,AppleAttestRegistryV1 previous_)
        AppleAttestRegistryV1(endorsements_,registry_,cds_,aaguid_,3,false) {
        require(address(previous_.cds())==address(cds_) && previous_.aaguid()==aaguid_ && previous_.keyACL()==keyACL
            && (previous_.validationCategory()==3 || previous_.validationCategory()==6),"previous registry policy");
        previous=previous_;
    }
    function migrate(bytes32 kid) external {
        _checkNewKey(kid);
        (uint256 x,uint256 y,uint64 expires,uint32 counter,bool enrolled)=previous.keys(kid);
        require(enrolled && block.timestamp<=expires && block.timestamp<=ROOT_NOT_AFTER,"key validity");
        keys[kid]=Key(x,y,expires,counter,true);
        emit Enrolled(kid,expires);
    }
}
