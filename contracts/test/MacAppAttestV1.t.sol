// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {MacAppAttestV1} from "../src/MacAppAttestV1.sol";
import {P256Verifier} from "./P256Verifier.sol";
import {AppleAuthData} from "../src/AppleAuthData.sol";
contract MacAppAttestV1Test is Test {
    MacAppAttestV1 adapter;bytes cert;bytes auth;bytes clientData;bytes32 kid;string fixture;
    function setUp() public {vm.warp(1789567200);load("fixtures/real-apple.json",3,false);}
    function load(string memory path,uint32 category,bool ios) internal {
        fixture=vm.readFile(path);
        cert=vm.parseJsonBytes(fixture,".cert");auth=vm.parseJsonBytes(fixture,".auth");clientData=vm.parseJsonBytes(fixture,".clientData");kid=vm.parseJsonBytes32(fixture,".kid");
        bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");bytes16 aaguid;assembly{aaguid:=mload(add(guid,32))}
        adapter=new MacAppAttestV1(address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),aaguid,category,ios);
        P256Verifier p=new P256Verifier();vm.etch(address(0x100),address(p).code);
    }
    function fresh() internal {vm.warp(1789588800);load("fixtures/fresh-apple.json",3,false);adapter.enroll(cert,auth,clientData);}
    function iphone() internal {vm.warp(1790200000);load("fixtures/iphone-apple.json",5,true);}
    function assertion(string memory name) internal view returns(bytes32 context,bytes memory proof){
        context=sha256(vm.parseJsonBytes(fixture,string.concat(".",name,".context")));
        proof=abi.encode(kid,vm.parseJsonBytes(fixture,string.concat(".",name,".auth")),uint256(vm.parseJsonBytes32(fixture,string.concat(".",name,".r"))),uint256(vm.parseJsonBytes32(fixture,string.concat(".",name,".s"))));
    }
    function test_FreshHardwareAssertionsAndModifiedCode() public {
        fresh();(bytes32 context,bytes memory proof)=assertion("assert");assertEq(adapter.verify(context,proof),kid);
        vm.expectRevert("assertion replay");adapter.verify(context,proof);
        (context,proof)=assertion("modified");vm.expectRevert("current CDHash");adapter.verify(context,proof);
        (context,proof)=assertion("restored");assertEq(adapter.verify(context,proof),kid);
        (,,,uint32 count,)=adapter.keys(kid);assertEq(count,3);
    }
    function test_FreshHardwareWrongContextRejected() public {
        fresh();(bytes32 context,bytes memory proof)=assertion("assert");
        vm.expectRevert("assertion signature");adapter.verify(context^bytes32(uint256(1)),proof);
        (,,,uint32 count,)=adapter.keys(kid);assertEq(count,0);
    }
    function test_FreshHardwareCannotResetCounterByReenrolling() public {
        fresh();vm.expectRevert("already enrolled");adapter.enroll(cert,auth,clientData);
    }
    function test_RealAppleEnrollment() public {assertEq(adapter.enroll(cert,auth,clientData),kid);(,,,,bool enrolled)=adapter.keys(kid);assertTrue(enrolled);}
    function test_ExpiredCertificateRejected() public {vm.warp(1790000000);vm.expectRevert("certificate validity");adapter.enroll(cert,auth,clientData);}
    function test_WrongNonceRejected() public {vm.expectRevert("certificate nonce");adapter.enroll(cert,auth,hex"00");}
    function test_TamperedSignatureRejected() public {cert[cert.length-1]^=0x01;vm.expectRevert("Apple certificate signature");adapter.enroll(cert,auth,clientData);}
    function test_TrailingCertificateRejected() public {vm.expectRevert("certificate trailing");adapter.enroll(bytes.concat(cert,hex"00"),auth,clientData);}
    function test_CounterCannotBeConsumedByUntrustedCaller() public {vm.prank(address(99));vm.expectRevert("registry only");adapter.verify(bytes32(0),"");}
    function test_WrongValidationCategoryRejected() public {
        bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");bytes16 aaguid;assembly{aaguid:=mload(add(guid,32))}
        MacAppAttestV1 other=new MacAppAttestV1(address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),aaguid,4,false);
        vm.expectRevert("validation category");other.enroll(cert,auth,clientData);
    }
    function test_IPhoneEnrollmentAndAssertions() public {
        iphone();assertEq(adapter.enroll(cert,auth,clientData),kid);
        (bytes32 context,bytes memory proof)=assertion("assert");assertEq(adapter.verify(context,proof),kid);
        (context,proof)=assertion("modified");vm.expectRevert("current CDHash");adapter.verify(context,proof);
        (,,,uint32 count,)=adapter.keys(kid);assertEq(count,1);
    }
    function test_IPhoneTamperedCDHashRejected() public {
        iphone();adapter.enroll(cert,auth,clientData);
        (bytes32 context,)=assertion("assert");bytes memory a=vm.parseJsonBytes(fixture,".assert.auth");a[70]^=0x01;
        bytes memory proof=abi.encode(kid,a,uint256(vm.parseJsonBytes32(fixture,".assert.r")),uint256(vm.parseJsonBytes32(fixture,".assert.s")));
        vm.expectRevert("current CDHash");adapter.verify(context,proof);
    }
    function test_IPhoneEvidenceRejectedUnderMacACL() public {
        iphone();bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");bytes16 aaguid;assembly{aaguid:=mload(add(guid,32))}
        MacAppAttestV1 mac=new MacAppAttestV1(address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),aaguid,5,false);
        vm.expectRevert("key ACL");mac.enroll(cert,auth,clientData);
    }
    function test_MacEvidenceRejectedUnderIOSACL() public {
        bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");bytes16 aaguid;assembly{aaguid:=mload(add(guid,32))}
        MacAppAttestV1 ios=new MacAppAttestV1(address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),aaguid,3,true);
        vm.expectRevert("key ACL");ios.enroll(cert,auth,clientData);
    }
}
