// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {DemoV1} from "../src/application/DemoV1.sol";
import {DemoV2} from "../src/application/DemoV2.sol";

// Synthetic admission/P-256 stubs isolate epoch and authorization behavior.
contract EpochTestAdmission {
    function verify(bytes32,bytes calldata) external pure returns(bytes32) {return bytes32(uint256(7));}
}
contract DemoV2Test is Test {
    DemoV2 demo;
    bytes32 category;
    uint256 constant SIGNER=123;
    address sponsor;

    function setUp() public {
        demo=new DemoV2(address(this));sponsor=vm.addr(SIGNER);
        category=demo.addCategory(bytes32(uint256(1)),bytes32(uint256(2)),address(new EpochTestAdmission()),true);
        demo.setCategoryEnabled(category,true);demo.setPaused(false);
        vm.mockCall(address(0x100),bytes(""),abi.encode(uint256(1)));
    }
    function request(DemoV1.Action action) internal view returns(DemoV1.Request memory r) {
        r=DemoV1.Request(action,category,sponsor,sponsor,bytes32(uint256(3)),demo.nonces(sponsor),uint64(block.timestamp+55),0,0,0,0);
        if(action==DemoV1.Action.Bootstrap || action==DemoV1.Action.Receipt){r.keyX=1;r.keyY=2;}
        if(action==DemoV1.Action.Receipt)r.envelopeDigest=bytes32(uint256(4));
    }
    function signature(DemoV1.Request memory r) internal view returns(bytes memory) {
        bytes32 digest=keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",demo.contextHash(r)));
        (uint8 v,bytes32 a,bytes32 b)=vm.sign(SIGNER,digest);return abi.encodePacked(a,b,v);
    }
    function execute(DemoV1.Request memory r) internal returns(bytes32) {
        bytes memory sig=signature(r);vm.prank(sponsor);
        return demo.execute(r,"",sig,r.action==DemoV1.Action.Join ? bytes(""):new bytes(64));
    }
    function test_EpochRecoveryPreservesNetworkAndMembers() public {
        bytes32 member=execute(request(DemoV1.Action.Join));
        execute(request(DemoV1.Action.Bootstrap));
        (,,,bool committed)=demo.sharedKeys(0);assertTrue(committed);
        demo.startKeyEpoch(0);
        (,,,committed)=demo.sharedKeys(0);assertFalse(committed);
        assertEq(demo.keyEpochs(0),1);assertTrue(demo.isActive(member));
        execute(request(DemoV1.Action.Bootstrap));
        (,,,committed)=demo.sharedKeys(0);assertTrue(committed);
    }
    function test_OldPendingReleaseSignatureRejectedAfterEpochChange() public {
        execute(request(DemoV1.Action.Bootstrap));
        DemoV1.Request memory r=request(DemoV1.Action.Receipt);bytes memory oldSignature=signature(r);
        bytes32 beforeHash=demo.contextHash(r);demo.startKeyEpoch(0);
        assertTrue(beforeHash!=demo.contextHash(r));
        vm.prank(sponsor);vm.expectRevert(DemoV1.InvalidProof.selector);
        demo.execute(r,"",oldSignature,new bytes(64));
    }
    function test_JoinContextDoesNotDependOnKeyEpoch() public {
        DemoV1.Request memory r=request(DemoV1.Action.Join);bytes32 beforeHash=demo.contextHash(r);
        demo.startKeyEpoch(0);assertEq(beforeHash,demo.contextHash(r));
    }
    function test_OnlyAdministratorCanStartEpoch() public {
        vm.prank(sponsor);vm.expectRevert(DemoV1.Unauthorized.selector);demo.startKeyEpoch(0);
    }
    function test_UnknownScopeRejected() public {
        vm.expectRevert(DemoV1.InvalidRequest.selector);demo.startKeyEpoch(bytes32(uint256(999)));
    }
}
