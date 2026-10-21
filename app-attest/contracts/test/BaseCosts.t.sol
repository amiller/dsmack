// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "../src/AppleEndorsements.sol";
import {EndorsementFixture as EF} from "./EndorsementFixture.sol";
import {GasFixture} from "./GasBreakdown.t.sol";
import {FeeMeasurement} from "./FeeMeasurement.sol";
contract BaseCostsTest is GasFixture,FeeMeasurement {
    function setUp() public {vm.warp(1789588800);load("fixtures/fresh-apple.json",3,false);}
    function test_SolidityEnrollmentCost() public {
        bytes memory data=abi.encodeCall(adapter.enroll,(cert,auth,clientData,EF.id()));vm.cool(address(adapter));
        (bool ok,bytes memory result)=address(adapter).call(data);
        if(!ok)assembly{revert(add(result,32),mload(result))}
        uint256 gas=vm.lastCallGas().gasTotalUsed;assertEq(abi.decode(result,(bytes32)),kid);fees(address(adapter),data,gas);
    }
    function test_AssertionCost() public {
        if(block.chainid==31337){vm.skip(true);return;}
        adapter.enroll(cert,auth,clientData,EF.id());(bytes32 context,bytes memory proof)=assertion("assert");
        bytes memory data=abi.encodeCall(adapter.verify,(context,proof));vm.cool(address(adapter));
        (bool ok,bytes memory result)=address(adapter).call(data);
        if(!ok)assembly{revert(add(result,32),mload(result))}
        uint256 gas=vm.lastCallGas().gasTotalUsed;assertEq(abi.decode(result,(bytes32)),kid);fees(address(adapter),data,gas);
    }
}
