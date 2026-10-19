// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";
import {AppleAuthData} from "../src/AppleAuthData.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {P256Verifier} from "./P256Verifier.sol";
contract Lookup is AppleAttestRegistryV1 {
    constructor(CDRegistry cds_,bytes16 aaguid_) AppleAttestRegistryV1(msg.sender,cds_,aaguid_,3,false){}
    function check(bytes memory auth) external view {(,,bytes32 cdhash,bytes32 rp)=AppleAuthData.check(auth,aaguid,false,0,0,validationCategory);admit(cdhash,rp);}
}
contract AppleAttestRegistryV1Test is Test {
    AppleAttestRegistryV1 adapter;CDRegistry cds;bytes cert;bytes auth;bytes clientData;bytes32 kid;bytes16 aaguid;string fixture;
    bytes32 constant OURS=0x90a07dc69293aa64c279caed89cfebd3fde0ad92b510f752ed45ba829157fff6;
    function setUp() public {P256Verifier p=new P256Verifier();vm.etch(address(0x100),address(p).code);}
    function load(string memory path,string memory build,uint32 category,bool ios,bool register) internal {
        fixture=vm.readFile(path);
        cert=vm.parseJsonBytes(fixture,".cert");auth=vm.parseJsonBytes(fixture,".auth");clientData=vm.parseJsonBytes(fixture,".clientData");kid=vm.parseJsonBytes32(fixture,".kid");
        bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");assembly{sstore(aaguid.slot,shr(128,mload(add(guid,32))))}
        string memory b=vm.readFile(build);bytes memory cd=vm.parseJsonBytes(b,".cd");bytes memory page0=vm.parseJsonBytes(b,".page0");bytes memory ent=vm.parseJsonBytes(b,".ent");
        cds=new CDRegistry();cds.setBuild(cd,page0,ent,vm.parseJsonUint(b,".linkeditCmd"),vm.parseJsonUint(b,".codeSigCmd"));
        if(register)assertEq(cds.registerBuild(cd,page0,ent),vm.parseJsonBytes32(fixture,".cdhash"));
        adapter=new AppleAttestRegistryV1(address(this),cds,aaguid,category,ios);
    }
    function mac(bool register) internal {vm.warp(1789588800);load("fixtures/fresh-apple.json","fixtures/cd-args-probe-macos.json",3,false,register);}
    function iphone(bool register) internal {vm.warp(1790200000);load("fixtures/iphone-apple.json","fixtures/resign/iphone-honest.json",5,true,register);}
    function assertion(string memory name) internal view returns(bytes32 context,bytes memory proof){
        context=sha256(vm.parseJsonBytes(fixture,string.concat(".",name,".context")));
        proof=abi.encode(kid,vm.parseJsonBytes(fixture,string.concat(".",name,".auth")),uint256(vm.parseJsonBytes32(fixture,string.concat(".",name,".r"))),uint256(vm.parseJsonBytes32(fixture,string.concat(".",name,".s"))));
    }
    function test_MacEnrollAndAssertThroughRegistry() public {
        mac(true);assertEq(adapter.enroll(cert,auth,clientData),kid);
        (bytes32 context,bytes memory proof)=assertion("assert");assertEq(adapter.verify(context,proof),kid);
        (context,proof)=assertion("modified");vm.expectRevert("build not admitted");adapter.verify(context,proof);
        (context,proof)=assertion("restored");assertEq(adapter.verify(context,proof),kid);
        (,,,uint32 count,)=adapter.keys(kid);assertEq(count,3);
    }
    function test_ReceiptEvidenceRequiresSuccessfulFreshAssertion() public {
        mac(true);adapter.enroll(cert,auth,clientData);
        (bytes32 recorded,,,,)=adapter.assertionEvidence(kid);assertEq(recorded,0);
        (bytes32 context,bytes memory proof)=assertion("assert");
        adapter.verify(context,proof);
        (bytes32 c,bytes32 cdhash,bytes32 rp,uint64 checkedAt,uint32 counter)=adapter.assertionEvidence(kid);
        assertEq(c,context);assertEq(cdhash,vm.parseJsonBytes32(fixture,".cdhash"));
        assertEq(rp,OURS);assertEq(checkedAt,block.timestamp);assertEq(counter,1);
        vm.expectRevert("assertion replay");adapter.verify(context,proof);
        (context,proof)=assertion("modified");
        vm.expectRevert("build not admitted");adapter.verify(context,proof);
        (recorded,,,,)=adapter.assertionEvidence(kid);assertEq(recorded,c);
        (context,proof)=assertion("restored");
        vm.expectRevert("assertion signature");adapter.verify(bytes32(uint256(123)),proof);
        (recorded,,,,)=adapter.assertionEvidence(kid);assertEq(recorded,c);
        adapter.verify(context,proof);
        (recorded,,,,counter)=adapter.assertionEvidence(kid);
        assertEq(recorded,context);assertEq(counter,3);
    }
    function test_MacUnregisteredBuildRejected() public {mac(false);vm.expectRevert("build not admitted");adapter.enroll(cert,auth,clientData);}
    function test_IPhoneEnrollAndAssertThroughRegistry() public {
        iphone(true);assertEq(adapter.enroll(cert,auth,clientData),kid);
        (bytes32 context,bytes memory proof)=assertion("assert");assertEq(adapter.verify(context,proof),kid);
        (context,proof)=assertion("modified");vm.expectRevert("build not admitted");adapter.verify(context,proof);
    }
    function test_IPhoneUnderMacProfileRejected() public {
        iphone(true);AppleAttestRegistryV1 m=new AppleAttestRegistryV1(address(this),cds,aaguid,5,false);
        vm.expectRevert("key ACL");m.enroll(cert,auth,clientData);
    }
    function test_IPhoneUnregisteredBuildRejected() public {iphone(false);vm.expectRevert("build not admitted");adapter.enroll(cert,auth,clientData);}
    function developerID(uint32 category) internal {
        string memory f=vm.readFile("fixtures/developer-id-apple.json");
        vm.warp(vm.parseJsonUint(f,".capturedAt"));
        load("fixtures/developer-id-apple.json","fixtures/cd-args-developer-id.json",category,false,true);
    }
    function test_DeveloperIDEnrollmentThroughRegistry() public {
        developerID(6);assertEq(adapter.enroll(cert,auth,clientData),kid);
    }
    function test_DeveloperIDNotAcceptedAsDevelopmentSigning() public {
        developerID(3);vm.expectRevert("validation category");adapter.enroll(cert,auth,clientData);
    }
    function test_ReleaseDevelopmentAndDeveloperIDShareCodeBaseline() public {
        developerID(6);
        string memory b=vm.readFile("fixtures/cd-args-release-development.json");
        assertEq(cds.registerBuild(vm.parseJsonBytes(b,".cd"),vm.parseJsonBytes(b,".page0"),vm.parseJsonBytes(b,".ent")),vm.parseJsonBytes32(b,".cdhash"));
    }
    function withBuild(bytes memory a,bytes32 rp,bytes32 cdhash) internal pure returns(bytes memory){assembly{mstore(add(a,32),rp) mstore(add(a,94),cdhash)}return a;}
    function jb(string memory j,string memory k) internal pure returns(bytes memory){return vm.parseJsonBytes(j,k);}
    /// Synthetic metadata on our node: CDHash/RP lookup isolation only, no Apple signature proof.
    function test_SyntheticTeamLookup() public {
        mac(true);bytes memory a=vm.parseJsonBytes(fixture,".assert.auth");
        string memory e=vm.readFile("fixtures/resign/node-honest.json");string memory o=vm.readFile("fixtures/resign/node-synthetic-team.json");
        cds=new CDRegistry();cds.setBuild(jb(e,".cd"),jb(e,".page0"),jb(e,".ent"),vm.parseJsonUint(e,".linkeditCmd"),vm.parseJsonUint(e,".codeSigCmd"));
        bytes32 eh=cds.registerBuild(jb(e,".cd"),jb(e,".page0"),jb(e,".ent"));bytes32 oh=cds.registerBuild(jb(o,".cd"),jb(o,".page0"),jb(o,".ent"));
        bytes32 erp=sha256("DC9JH5DRMY.dev.dsmack.provider");bytes32 orp=sha256("TESTTEAM01.dev.dsmack.provider");
        Lookup l=new Lookup(cds,aaguid);
        l.check(withBuild(a,erp,eh));l.check(withBuild(a,orp,oh));
        vm.expectRevert("build not admitted");l.check(withBuild(a,erp,oh));
        vm.expectRevert("build not admitted");l.check(withBuild(a,orp,eh));
    }
}
