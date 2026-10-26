// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {EndorsementFixture as EF} from "../EndorsementFixture.sol";
import {Test} from "forge-std/Test.sol";
import {AppleAttestZK,IAppleAttestVerifier} from "attest/AppleAttestZK.sol";
import {MacAppAttestZKV1} from "attest/MacAppAttestZKV1.sol";
contract LeafEnrollmentTest is Test {
    uint128[6] key;bytes32 subject;
    function deployVerifier(string memory variant) internal returns(IAppleAttestVerifier){
        string memory name=string.concat("HonkVerifier",variant,".sol");
        bytes memory code=vm.getCode(string.concat("verifier/out/",name,"/ZKTranscriptLib.json"));address lib;assembly{lib:=create(0,add(code,32),mload(code))}require(lib!=address(0),"library deployment");
        string memory artifact=vm.readFile(string.concat("verifier/out/",name,"/HonkVerifier.json"));
        string memory object=vm.parseJsonString(artifact,".bytecode.object");
        string[] memory sources=vm.parseJsonKeys(artifact,".bytecode.linkReferences");require(sources.length==1,"verifier link source");
        uint256 start=vm.parseJsonUint(artifact,string.concat(".bytecode.linkReferences['",sources[0],"'].ZKTranscriptLib[0].start"));
        bytes memory obj=bytes(object);bytes memory addr=bytes(vm.replace(vm.toString(lib),"0x",""));
        for(uint256 i;i<40;i++)obj[2*start+2+i]=addr[i];
        code=vm.parseBytes(string(obj));address honk;assembly{honk:=create(0,add(code,32),mload(code))}require(honk!=address(0),"verifier deployment");return IAppleAttestVerifier(honk);
    }
    function load(bool ios,bool fresh) internal returns(MacAppAttestZKV1 adapter,bytes memory proof,bytes memory client,AppleAttestZK.PublicValues memory p,string memory f){
        string memory base=fresh?"../circuit/proofs/leaf/fresh/":string.concat("../circuit/proofs/leaf/",ios?"iphone/":"mac/");
        proof=vm.readFileBinary(string.concat(base,"proof"));bytes memory raw=vm.readFileBinary(string.concat(base,"public_inputs"));require(raw.length==768,"public size");
        uint256[24] memory v;for(uint256 i;i<24;i++){uint256 word;assembly{word:=mload(add(add(raw,32),mul(i,32)))}v[i]=word;}
        p=AppleAttestZK.PublicValues(bytes32(v[0]<<128|v[1]),bytes32(v[2]<<128|v[3]),bytes32(v[4]<<128|v[5]),v[6]<<128|v[7],v[8]<<128|v[9],uint64(v[10]),uint64(v[11]),bytes16(uint128(v[12])),uint32(v[13]),bytes32(v[14]<<128|v[15]));
        assertEq(p.aaguid,hex"61707061747465737400000000000000");assertEq(p.validationCategory,ios?5:3);
        for(uint256 i;i<6;i++)key[i]=uint128(v[16+i]);subject=bytes32(v[22]<<128|v[23]);
        vm.warp(p.notBefore+(p.notAfter-p.notBefore)/2);
        adapter=new MacAppAttestZKV1(new AppleEndorsements(),address(this),p.rpIdHash,p.cdhash,hex"61707061747465737400000000000000",ios?5:3,ios,deployVerifier("Leaf"));
        assertEq(adapter.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/apple-intermediate.der")),EF.id());
        f=vm.readFile(fresh?"fixtures/fresh-apple.json":ios?"fixtures/iphone-apple.json":"fixtures/real-apple.json");client=vm.parseJsonBytes(f,".clientData");
        assertEq(p.clientDataHash,sha256(client));assertEq(p.rpIdHash,vm.parseJsonBytes32(f,".appHash"));assertEq(p.cdhash,vm.parseJsonBytes32(f,".cdhash"));
    }
    function run(bool ios,bool fresh) internal {
        (MacAppAttestZKV1 a,bytes memory proof,bytes memory client,AppleAttestZK.PublicValues memory p,string memory f)=load(ios,fresh);
        bytes32 kid=vm.parseJsonBytes32(f,".kid");assertEq(a.enrollLeafProof(proof,client,p,key,EF.id()),kid);
        (uint256 x,uint256 y,uint64 expiry,uint32 count,bool enrolled)=a.keys(kid);assertEq(x,p.x);assertEq(y,p.y);(,,,uint64 end)=a.endorsements().intermediates(EF.id());assertEq(expiry,end);assertEq(count,0);assertTrue(enrolled);
        if(!ios && !fresh)return; // real-apple.json has no assertion for this key.
        bytes32 context=sha256(vm.parseJsonBytes(f,".assert.context"));bytes memory assertion=abi.encode(kid,vm.parseJsonBytes(f,".assert.auth"),uint256(vm.parseJsonBytes32(f,".assert.r")),uint256(vm.parseJsonBytes32(f,".assert.s")));
        assertEq(a.verify(context,assertion),kid);
        (,,,count,)=a.keys(kid);assertEq(count,1);vm.expectRevert("assertion replay");a.verify(context,assertion);
    }
    function negative(bool ios) internal {
        (MacAppAttestZKV1 a,bytes memory proof,bytes memory client,AppleAttestZK.PublicValues memory p,)=load(ios,false);
        for(uint256 i;i<16;i++){
            AppleAttestZK.PublicValues memory q=abi.decode(abi.encode(p),(AppleAttestZK.PublicValues));
            if(i<2)q.rpIdHash^=bytes32(uint256(1)<<(i==0?128:0));
            else if(i<4)q.cdhash^=bytes32(uint256(1)<<(i==2?128:0));
            else if(i<6)q.clientDataHash^=bytes32(uint256(1)<<(i==4?128:0));
            else if(i<8)q.x^=uint256(1)<<(i==6?128:0);
            else if(i<10)q.y^=uint256(1)<<(i==8?128:0);
            else if(i==10)q.notBefore--;else if(i==11)q.notAfter--;else if(i==12)q.aaguid^=bytes16(uint128(1));else if(i==13)q.validationCategory++;
            else q.keyACLHash^=bytes32(uint256(1)<<(i==14?128:0));
            if(i<2)vm.expectRevert("app identity");else if(i<4)vm.expectRevert("current CDHash");
            else if(i<6)vm.expectRevert("client data hash");else if(i<12)vm.expectRevert(bytes4(keccak256("SumcheckFailed()")));
            else if(i==12)vm.expectRevert("aaguid");else if(i==13)vm.expectRevert("validation category");else vm.expectRevert("key ACL");
            a.enrollLeafProof(proof,client,q,key,EF.id());
        }
        vm.expectRevert("intermediate validity");a.enrollLeafProof(proof,client,p,key,bytes32(0));
        for(uint256 i;i<6;i++){key[i]^=1;vm.expectRevert("intermediate key");a.enrollLeafProof(proof,client,p,key,EF.id());key[i]^=1;}
        uint64 before_=p.notBefore;uint64 after_=p.notAfter;
        p.notBefore=uint64(block.timestamp+1);vm.expectRevert("certificate validity");a.enrollLeafProof(proof,client,p,key,EF.id());p.notBefore=before_;
        p.notAfter=uint64(block.timestamp-1);vm.expectRevert("certificate validity");a.enrollLeafProof(proof,client,p,key,EF.id());p.notAfter=after_;
        proof[100]^=0x01;vm.expectRevert(bytes4(keccak256("SumcheckFailed()")));a.enrollLeafProof(proof,client,p,key,EF.id());
        (,,,,bool enrolled)=a.keys(sha256(abi.encodePacked(bytes1(0x04),p.x,p.y)));assertFalse(enrolled);
    }
    function test_IntermediateExpiryCap() public {
        (MacAppAttestZKV1 a,bytes memory proof,bytes memory client,AppleAttestZK.PublicValues memory p,)=load(false,false);
        // Shorten only the authenticated record's expiry to isolate the storage cap.
        bytes32 slot=bytes32(uint256(keccak256(abi.encode(EF.id(),uint256(0))))+5);
        uint256 packed=uint256(vm.load(address(a.endorsements()),slot));uint64 end=uint64(block.timestamp+1);
        vm.store(address(a.endorsements()),slot,bytes32(uint256(uint64(packed))|(uint256(end)<<64)));
        (,,,uint64 stored)=a.endorsements().intermediates(EF.id());assertEq(stored,end);
        bytes32 kid=a.enrollLeafProof(proof,client,p,key,EF.id());(,,uint64 expiry,,)=a.keys(kid);assertEq(expiry,end);
    }
    function test_ExpiredEndorsement() public {
        (MacAppAttestZKV1 a,bytes memory proof,bytes memory client,AppleAttestZK.PublicValues memory p,)=load(false,false);
        (,,,uint64 end)=a.endorsements().intermediates(EF.id());vm.warp(uint256(end)+1);
        vm.expectRevert("intermediate validity");a.enrollLeafProof(proof,client,p,key,EF.id());
    }
    function test_FutureEndorsement() public {
        (MacAppAttestZKV1 a,bytes memory proof,bytes memory client,AppleAttestZK.PublicValues memory p,)=load(false,false);
        (,,uint64 start,)=a.endorsements().intermediates(EF.id());vm.warp(uint256(start)-1);
        vm.expectRevert("intermediate validity");a.enrollLeafProof(proof,client,p,key,EF.id());
    }
    function test_MacEnrollment() public {run(false,false);}
    function test_FreshMacEnrollmentAndAssertion() public {run(false,true);}
    function test_IPhoneEnrollmentAndAssertion() public {run(true,false);}
    function test_MacMutations() public {negative(false);}
    function test_IPhoneMutations() public {negative(true);}
}
