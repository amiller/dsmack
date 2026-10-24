// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "../src/AppleEndorsements.sol";
import {Test} from "forge-std/Test.sol";
import {MacAppAttestV1} from "../src/MacAppAttestV1.sol";
abstract contract AttestFixture is Test {
    MacAppAttestV1 adapter;bytes cert;bytes auth;bytes clientData;bytes32 kid;string fixture;
    function load(string memory path,uint32 category,bool ios) internal {
        fixture=vm.readFile(path);
        cert=vm.parseJsonBytes(fixture,".cert");auth=vm.parseJsonBytes(fixture,".auth");clientData=vm.parseJsonBytes(fixture,".clientData");kid=vm.parseJsonBytes32(fixture,".kid");
        bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");bytes16 aaguid;assembly{aaguid:=mload(add(guid,32))}
        adapter=new MacAppAttestV1(new AppleEndorsements(),address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),aaguid,category,ios);adapter.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/apple-intermediate.der"));
    }
}
