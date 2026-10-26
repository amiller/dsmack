// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {EndorsementFixture as EF} from "attest-test/EndorsementFixture.sol";
import {Test} from "forge-std/Test.sol";
import {AppleAttestZK,IAppleAttestVerifier} from "attest/AppleAttestZK.sol";
import {RotationEndorsements} from "attest-test/EndorsementFixture.sol";
import {MacAppAttestZKV1} from "attest/MacAppAttestZKV1.sol";
import {MacAppAttestV1} from "attest/MacAppAttestV1.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {AppleLeaf} from "attest/AppleLeaf.sol";
import {P256Verifier} from "attest-test/P256Verifier.sol";

contract MockAttestVerifier is IAppleAttestVerifier {
    bytes32 public expected;bool public accepts=true;
    function configure(bytes32 hash,bool ok) external {expected=hash;accepts=ok;}
    function verify(bytes calldata proof,bytes32[] calldata inputs) external view returns(bool){
        require(keccak256(proof)==keccak256(hex"1234"),"proof bytes");
        require(keccak256(abi.encode(inputs))==expected,"public inputs");return accepts;
    }
}
contract AppleAttestZKTest is Test {
    MacAppAttestZKV1 adapter;MockAttestVerifier mock;AppleAttestZK.PublicValues p;bytes client;bytes32 kid;string fixture;
    function setUp() public {load("../app-attest/contracts/fixtures/fresh-apple.json",false);}
    function load(string memory path,bool ios) internal {
        vm.warp(ios?1790200000:1789588800);fixture=vm.readFile(path);client=vm.parseJsonBytes(fixture,".clientData");kid=vm.parseJsonBytes32(fixture,".kid");
        bytes16 guid=bytes16(vm.parseJsonBytes(fixture,".aaguid"));mock=new MockAttestVerifier();
        adapter=new MacAppAttestZKV1(new AppleEndorsements(),address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),guid,ios?5:3,ios,mock);
        AppleLeaf.Parsed memory leaf=AppleLeaf.parse(vm.parseJsonBytes(fixture,".cert"),0x46204201d1f19bafcf31fc60e9ebfd04be6ff265b93b9ba037196d24095f6c10,sha256(abi.encodePacked(vm.parseJsonBytes(fixture,".auth"),sha256(client))),adapter.keyACL());
        p=AppleAttestZK.PublicValues(vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),sha256(client),leaf.x,leaf.y,uint64(block.timestamp),leaf.expires,guid,ios?5:3,adapter.keyACLSHA256());
        adapter.endorsements().endorseIntermediate(vm.readFileBinary("../app-attest/contracts/fixtures/apple-intermediate.der"));
        configure(EF.key(),0x46204201d1f19bafcf31fc60e9ebfd04be6ff265b93b9ba037196d24095f6c10);
    }
    function configure(uint128[6] memory key,bytes32 subject) internal {
        bytes32[] memory inputs=new bytes32[](24);
        inputs[0]=bytes32(uint256(p.rpIdHash)>>128);inputs[1]=bytes32(uint256(uint128(uint256(p.rpIdHash))));
        inputs[2]=bytes32(uint256(p.cdhash)>>128);inputs[3]=bytes32(uint256(uint128(uint256(p.cdhash))));
        inputs[4]=bytes32(uint256(p.clientDataHash)>>128);inputs[5]=bytes32(uint256(uint128(uint256(p.clientDataHash))));
        inputs[6]=bytes32(p.x>>128);inputs[7]=bytes32(uint256(uint128(p.x)));inputs[8]=bytes32(p.y>>128);inputs[9]=bytes32(uint256(uint128(p.y)));
        inputs[10]=bytes32(uint256(p.notBefore));inputs[11]=bytes32(uint256(p.notAfter));inputs[12]=bytes32(uint256(uint128(p.aaguid)));inputs[13]=bytes32(uint256(p.validationCategory));
        inputs[14]=bytes32(uint256(p.keyACLHash)>>128);inputs[15]=bytes32(uint256(uint128(uint256(p.keyACLHash))));
        for(uint256 i;i<6;i++)inputs[16+i]=bytes32(uint256(key[i]));
        inputs[22]=bytes32(uint256(subject)>>128);inputs[23]=bytes32(uint256(uint128(uint256(subject))));
        mock.configure(keccak256(abi.encode(inputs)),true);
    }
    function enroll() internal {assertEq(adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id()),kid);}
    function assertion() internal {
        bytes32 context=sha256(vm.parseJsonBytes(fixture,".assert.context"));
        bytes memory proof=abi.encode(kid,vm.parseJsonBytes(fixture,".assert.auth"),uint256(vm.parseJsonBytes32(fixture,".assert.r")),uint256(vm.parseJsonBytes32(fixture,".assert.s")));
        if(block.chainid==31337){P256Verifier v=new P256Verifier();vm.etch(address(0x100),address(v).code);}
        assertEq(adapter.verify(context,proof),kid);(,,,uint32 count,)=adapter.keys(kid);assertEq(count,1);
        vm.expectRevert("assertion replay");adapter.verify(context,proof);
    }
    function test_EmptyPolicy() public {
        AppleEndorsements e=adapter.endorsements();
        vm.expectRevert("empty policy");new MacAppAttestZKV1(e,address(this),bytes32(0),bytes32(uint256(1)),hex"61707061747465737400000000000000",3,false,mock);
        vm.expectRevert("empty policy");new MacAppAttestZKV1(e,address(this),bytes32(uint256(1)),bytes32(0),hex"61707061747465737400000000000000",3,false,mock);
    }
    function intermediateEnd() internal view returns(uint64 end){(,,,end)=adapter.endorsements().intermediates(EF.id());}
    function test_EnrollmentAndAssertion() public {enroll();(uint256 x,uint256 y,uint64 expires,uint32 count,bool ok)=adapter.keys(kid);assertEq(x,p.x);assertEq(y,p.y);assertEq(expires,intermediateEnd());assertEq(count,0);assertTrue(ok);assertion();}
    function test_IOS() public {load("../app-attest/contracts/fixtures/iphone-apple.json",true);enroll();assertion();}
    function nativeEnroll(bytes memory data) internal {adapter.enroll(vm.parseJsonBytes(fixture,".cert"),vm.parseJsonBytes(fixture,".auth"),data,EF.id());}
    function test_NativeClientLength() public {vm.expectRevert("anchor expiry/client data");nativeEnroll(new bytes(2049));}
    function test_NativeAnchorExpiry() public {vm.warp(adapter.ROOT_NOT_AFTER()+1);vm.expectRevert("anchor expiry/client data");nativeEnroll(client);}
    function test_NativeThenProofReplay() public {nativeEnroll(client);vm.expectRevert("already enrolled");adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());}
    function test_ProofThenNativeReplay() public {enroll();vm.expectRevert("already enrolled");nativeEnroll(client);}
    function test_OtherPlatformProof() public {
        MacAppAttestZKV1 mac=adapter;load("../app-attest/contracts/fixtures/iphone-apple.json",true);
        vm.expectRevert("validation category");mac.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());
    }
    function test_Duplicate() public {enroll();vm.expectRevert("already enrolled");adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());}
    function test_ClientLength() public {vm.expectRevert("anchor expiry/client data");adapter.enrollLeafProof(hex"1234",new bytes(2049),p,EF.key(),EF.id());}
    function test_AnchorExpiry() public {vm.warp(2373148801);vm.expectRevert("anchor expiry/client data");adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());}
    function test_TimeBounds() public {vm.warp(p.notBefore-1);vm.expectRevert("certificate validity");adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());vm.warp(p.notAfter+1);vm.expectRevert("certificate validity");adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());}
    function test_VerifierFalse() public {mock.configure(mock.expected(),false);vm.expectRevert("attestation proof");adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());(,,,,bool ok)=adapter.keys(kid);assertFalse(ok);}
    function test_ProofMismatch() public {vm.expectRevert("proof bytes");adapter.enrollLeafProof(hex"1235",client,p,EF.key(),EF.id());}
    function test_AllPublicFields() public {
        AppleAttestZK.PublicValues memory original=p;
        for(uint8 i;i<16;i++){p=original;this.testFuzz_EachPublicFieldMismatch(i);}
    }
    function test_ValidityEndpoints() public {
        uint256 snapshot=vm.snapshotState();enroll();assertTrue(vm.revertToState(snapshot));vm.warp(p.notAfter);enroll();
    }
    function test_AllAdaptersShareOneEndorsement() public {
        AppleEndorsements e=adapter.endorsements();
        MacAppAttestV1 mac=new MacAppAttestV1(e,address(this),p.rpIdHash,p.cdhash,p.aaguid,3,false);
        CDRegistry cds=new CDRegistry();string memory b=vm.readFile("fixtures/cd-args-probe-macos.json");
        bytes memory cd=vm.parseJsonBytes(b,".cd");bytes memory page=vm.parseJsonBytes(b,".page0");bytes memory ent=vm.parseJsonBytes(b,".ent");
        cds.setBuild(cd,page,ent);cds.registerBuild(cd,page,ent);
        AppleAttestRegistryV1 reg=new AppleAttestRegistryV1(e,address(this),cds,p.aaguid,3,false);
        bytes memory cert=vm.parseJsonBytes(fixture,".cert");bytes memory auth=vm.parseJsonBytes(fixture,".auth");
        assertEq(mac.enroll(cert,auth,client,EF.id()),kid);assertEq(reg.enroll(cert,auth,client,EF.id()),kid);
        assertEq(adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id()),kid);
        assertEq(address(mac.endorsements()),address(reg.endorsements()));assertEq(address(reg.endorsements()),address(adapter.endorsements()));
        vm.expectRevert("already endorsed");e.endorseIntermediate(vm.readFileBinary("../app-attest/contracts/fixtures/apple-intermediate.der"));
    }
    function test_ProofEntryBinding() public {
        vm.expectRevert("intermediate validity");
        adapter.enrollLeafProof(hex"1234",client,p,EF.key(),bytes32(0));
        for(uint256 i;i<6;i++){
            uint128[6] memory key=EF.key();key[i]^=1;vm.expectRevert("intermediate key");
            adapter.enrollLeafProof(hex"1234",client,p,key,EF.id());
        }
    }
    function test_SameSubject() public {
        RotationEndorsements e=new RotationEndorsements();
        bytes32 id2=e.endorseIntermediate(vm.readFileBinary("../app-attest/contracts/fixtures/rotation/ca2.der"));
        bytes32 prior=keccak256(abi.encode(e.get(id2)));
        bytes32 id3=e.endorseIntermediate(vm.readFileBinary("../app-attest/contracts/fixtures/rotation/ca3.der"));
        assertTrue(id2!=id3);assertEq(e.get(id2).subject,e.get(id3).subject);
        assertEq(keccak256(abi.encode(e.get(id2))),prior);
        for(uint256 i=2;i<=3;i++){
            string memory f=vm.readFile(i==2?"../app-attest/contracts/fixtures/real-apple.json":"../app-attest/contracts/fixtures/fresh-apple.json");
            client=vm.parseJsonBytes(f,".clientData");bytes32 id=i==2?id2:id3;
            AppleEndorsements.Intermediate memory ca=e.get(id);
            uint128[6] memory key=[uint128(ca.key.xhi),uint128(ca.key.xlo>>128),uint128(ca.key.xlo),uint128(ca.key.yhi),uint128(ca.key.ylo>>128),uint128(ca.key.ylo)];
            adapter=new MacAppAttestZKV1(e,address(this),vm.parseJsonBytes32(f,".appHash"),vm.parseJsonBytes32(f,".cdhash"),p.aaguid,3,false,mock);
            AppleLeaf.Parsed memory leaf=AppleLeaf.parse(vm.readFileBinary(i==2?"../app-attest/contracts/fixtures/rotation/leaf2.der":"../app-attest/contracts/fixtures/rotation/leaf3.der"),ca.subject,sha256(abi.encodePacked(vm.parseJsonBytes(f,".auth"),sha256(client))),adapter.keyACL());
            p.rpIdHash=vm.parseJsonBytes32(f,".appHash");p.cdhash=vm.parseJsonBytes32(f,".cdhash");p.clientDataHash=sha256(client);p.x=leaf.x;p.y=leaf.y;p.notAfter=leaf.expires;
            configure(key,ca.subject);bytes32 expected=vm.parseJsonBytes32(f,".kid");
            if(i==2){vm.expectRevert("intermediate key");adapter.enrollLeafProof(hex"1234",client,p,key,id3);}
            assertEq(adapter.enrollLeafProof(hex"1234",client,p,key,id),expected);
        }
        assertEq(keccak256(abi.encode(e.get(id2))),prior);
    }
    function test_After2030() public {
        vm.warp(1938297600);RotationEndorsements e=new RotationEndorsements();
        bytes32 id=e.endorseIntermediate(vm.readFileBinary("../app-attest/contracts/fixtures/rotation/ca5.der"));
        adapter=new MacAppAttestZKV1(e,address(this),p.rpIdHash,p.cdhash,p.aaguid,3,false,mock);
        AppleEndorsements.Intermediate memory ca=e.get(id);
        uint128[6] memory key=[uint128(ca.key.xhi),uint128(ca.key.xlo>>128),uint128(ca.key.xlo),uint128(ca.key.yhi),uint128(ca.key.ylo>>128),uint128(ca.key.ylo)];
        p.notBefore=uint64(block.timestamp);p.notAfter=uint64(block.timestamp+100);
        configure(key,ca.subject);
        assertEq(adapter.enrollLeafProof(hex"1234",client,p,key,id),kid);assertion();
    }
    function test_ACLCommitments() public {
        bytes memory acl=hex"3046a344044230400c023131303a30090c026f6ba1030101ff30090c026f61a1030101ff300b0c046f64656ca1030101ff30150c046f73676ea0060c04727365633005a603020101";
        assertEq(adapter.keyACL(),keccak256(acl));assertEq(adapter.keyACLSHA256(),sha256(acl));
        load("../app-attest/contracts/fixtures/iphone-apple.json",true);
        acl=hex"3049a347044530430c023131303d300a0c036f6b64a1030101ff30090c026f61a1030101ff300b0c046f73676ea1030101ff300b0c046f64656ca1030101ff300a0c036f636ba1030101ff";
        assertEq(adapter.keyACL(),keccak256(acl));assertEq(adapter.keyACLSHA256(),sha256(acl));
    }
    function testFuzz_EachPublicFieldMismatch(uint8 field) public {
        uint256 i=uint256(field)%16;string memory reason;
        if(i<2){p.rpIdHash^=bytes32(uint256(1)<<(i==0?128:0));reason="app identity";}
        else if(i<4){p.cdhash^=bytes32(uint256(1)<<(i==2?128:0));reason="current CDHash";}
        else if(i<6){p.clientDataHash^=bytes32(uint256(1)<<(i==4?128:0));reason="client data hash";}
        else if(i<8){p.x^=uint256(1)<<(i==6?128:0);reason="public inputs";}
        else if(i<10){p.y^=uint256(1)<<(i==8?128:0);reason="public inputs";}
        else if(i==10){p.notBefore--;reason="public inputs";}
        else if(i==11){p.notAfter--;reason="public inputs";}
        else if(i==12){p.aaguid^=bytes16(uint128(1));reason="aaguid";}
        else if(i==13){p.validationCategory++;reason="validation category";}
        else {p.keyACLHash^=bytes32(uint256(1)<<(i==14?128:0));reason="key ACL";}
        vm.expectRevert(bytes(reason));adapter.enrollLeafProof(hex"1234",client,p,EF.key(),EF.id());
    }
}
