// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "../src/AppleEndorsements.sol";
import {RotationEndorsements} from "./EndorsementFixture.sol";
import {MacAppAttestV1} from "../src/MacAppAttestV1.sol";
import {P256Verifier} from "./P256Verifier.sol";
import {AppleAttest} from "../src/AppleAttest.sol";
import {P384} from "../src/P384.sol";
import {StrictDER as D} from "../src/StrictDER.sol";
import {AttestFixture} from "./AttestFixture.sol";
contract RotationAttest is AppleAttest {
    constructor(bytes16 guid) AppleAttest(new RotationEndorsements(),msg.sender,guid,3,false){}
    function admit(bytes32,bytes32) internal pure override {}
}
contract IntermediateTest is AttestFixture {
    bytes ca;
    bytes32 constant SUBJECT=0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90;
    function setUp() public {vm.warp(1789567200);load("fixtures/real-apple.json",3,false);ca=vm.readFileBinary("fixtures/apple-intermediate.der");}
    function changed(bytes memory b,bytes memory needle,uint256 offset,bytes1 value) internal pure returns(bytes memory){
        for(uint256 i;i+needle.length<=b.length;i++){
            bool same=true;for(uint256 j;j<needle.length;j++)if(b[i+j]!=needle[j]){same=false;break;}
            if(same){b[i+offset]=value;return b;}
        }
        revert("mutation not found");
    }
    function reject(bytes memory b,string memory reason) internal {AppleEndorsements e=adapter.endorsements();vm.expectRevert(bytes(reason));e.endorseIntermediate(b);}
    function test_EndorseReal() public {
        AppleEndorsements e=adapter.endorsements();vm.expectRevert("already endorsed");e.endorseIntermediate(ca);
        (,P384.C384Elm memory key,uint64 before_,uint64 after_)=adapter.endorsements().intermediates(SUBJECT);
        assertEq(key.xhi,0xae5b37a0774d79b2358f40e7d1f22626);assertEq(key.xlo,0xf1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706);
        assertEq(key.yhi,0x9e98d363bd5e370fbfa08e329e8073a9);assertEq(key.ylo,0x85e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99);
        assertLe(before_,block.timestamp);assertGe(after_,block.timestamp);
    }
    function test_RootSignature() public {ca[ca.length-1]^=0x01;reject(ca,"root certificate signature");}
    function test_Algorithm() public {
        D.Node memory outer=D.expect(ca,0,ca.length,0x30);D.Node memory tbs=D.expect(ca,outer.body,outer.end,0x30);
        D.Node memory alg=D.expect(ca,tbs.end,outer.end,0x30);ca[alg.end-1]=0x02;reject(ca,"signature algorithm");
    }
    function test_InnerAlgorithm() public {reject(changed(ca,hex"300a06082a8648ce3d040303",11,0x02),"inner signature algorithm");}
    function test_NonCA() public {reject(changed(ca,hex"30060101ff020100",4,0x00),"CA constraints");}
    function test_Usage() public {reject(changed(ca,hex"03020106",3,0x04),"CA usage");}
    function test_ConstraintsCritical() public {reject(changed(ca,hex"0603551d130101ff",7,0x00),"critical encoding");}
    function test_UsageCritical() public {reject(changed(ca,hex"0603551d0f0101ff",7,0x00),"critical encoding");}
    function test_SPKI() public {reject(changed(ca,hex"06052b81040022",6,0x23),"P384 SPKI");}
    function test_PointEncoding() public {reject(changed(ca,hex"03620004",3,0x02),"public key encoding");}
    function test_Expired() public {(,,,uint64 end)=adapter.endorsements().intermediates(SUBJECT);vm.warp(uint256(end)+1);reject(ca,"certificate validity");}
    function test_Future() public {(,,uint64 start,)=adapter.endorsements().intermediates(SUBJECT);vm.warp(uint256(start)-1);reject(ca,"certificate validity");}
    function test_Trailing() public {reject(bytes.concat(ca,hex"00"),"certificate trailing");}
    function test_NoEndorsement() public {vm.expectRevert("intermediate validity");adapter.enroll(cert,auth,clientData,bytes32(0));}
    function test_IssuerMismatch() public {
        cert=changed(cert,bytes("Apple App Attestation CA 1"),0,0x42);
        vm.expectRevert("issuer name");adapter.enroll(cert,auth,clientData,SUBJECT);
    }
    function test_ExpiredEndorsement() public {
        RotationAttest r=new RotationAttest(adapter.aaguid());bytes32 subject=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca2.der"));
        (,,,uint64 end)=r.endorsements().intermediates(subject);vm.warp(uint256(end)+1);vm.expectRevert("intermediate validity");r.enroll(cert,auth,clientData,subject);
    }
    function test_FutureEndorsement() public {
        RotationAttest r=new RotationAttest(adapter.aaguid());bytes32 subject=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca2.der"));
        (,,uint64 start,)=r.endorsements().intermediates(subject);vm.warp(uint256(start)-1);vm.expectRevert("intermediate validity");r.enroll(cert,auth,clientData,subject);
    }
    function test_SameSubjectWrongKey() public {
        RotationAttest r=new RotationAttest(adapter.aaguid());
        bytes32 a=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca2.der"));
        bytes32 b=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca3.der"));
        assertTrue(a!=b);assertEq(r.endorsements().get(a).subject,r.endorsements().get(b).subject);
        vm.expectRevert("Apple certificate signature");
        r.enroll(vm.readFileBinary("fixtures/rotation/leaf2.der"),auth,clientData,b);
    }
    function test_Rotation() public {
        RotationAttest r=new RotationAttest(adapter.aaguid());
        bytes32 s2=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca2.der"));
        assertEq(r.enroll(vm.readFileBinary("fixtures/rotation/leaf2.der"),auth,clientData,s2),kid);
        bytes32 prior=keccak256(abi.encode(r.endorsements().get(s2)));
        AppleEndorsements e=r.endorsements();vm.expectRevert("already endorsed");e.endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca2-reissued.der"));
        assertEq(keccak256(abi.encode(r.endorsements().get(s2))),prior);
        bytes32 s3=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca3.der"));assertTrue(s2!=s3);
        assertEq(keccak256(abi.encode(r.endorsements().get(s2))),prior);
        assertEq(r.endorsements().get(s2).subject,r.endorsements().get(s3).subject);
        bytes32 current=keccak256(abi.encode(r.endorsements().get(s3)));
        vm.warp(1789588800);string memory f=vm.readFile("fixtures/fresh-apple.json");
        assertEq(r.enroll(vm.readFileBinary("fixtures/rotation/leaf3.der"),vm.parseJsonBytes(f,".auth"),vm.parseJsonBytes(f,".clientData"),s3),vm.parseJsonBytes32(f,".kid"));
        assertEq(keccak256(abi.encode(r.endorsements().get(s2))),prior);
        assertEq(keccak256(abi.encode(r.endorsements().get(s3))),current);
    }
    function test_After2030EnrollmentAndAssertion() public {
        P256Verifier v=new P256Verifier();vm.etch(address(0x100),address(v).code);
        vm.warp(1938297600);RotationAttest r=new RotationAttest(adapter.aaguid());
        bytes32 id=r.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/rotation/ca5.der"));
        string memory f=vm.readFile("fixtures/fresh-apple.json");bytes32 k=vm.parseJsonBytes32(f,".kid");
        assertEq(r.enroll(vm.readFileBinary("fixtures/rotation/leaf5.der"),vm.parseJsonBytes(f,".auth"),vm.parseJsonBytes(f,".clientData"),id),k);
        bytes memory proof=abi.encode(k,vm.parseJsonBytes(f,".assert.auth"),uint256(vm.parseJsonBytes32(f,".assert.r")),uint256(vm.parseJsonBytes32(f,".assert.s")));
        assertEq(r.verify(sha256(vm.parseJsonBytes(f,".assert.context")),proof),k);
        vm.warp(2373148801);vm.expectRevert("key validity");r.verify(bytes32(0),proof);
    }
    function test_SharedEndorsement() public {
        MacAppAttestV1 other=new MacAppAttestV1(adapter.endorsements(),address(this),adapter.appHash(),adapter.approvedCDHash(),adapter.aaguid(),3,false);
        assertEq(other.enroll(cert,auth,clientData,SUBJECT),kid);assertEq(adapter.enroll(cert,auth,clientData,SUBJECT),kid);
        assertEq(address(other.endorsements()),address(adapter.endorsements()));
    }
}
