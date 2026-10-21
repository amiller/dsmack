// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "../src/AppleEndorsements.sol";
import {EndorsementFixture as EF} from "./EndorsementFixture.sol";
import {Test} from "forge-std/Test.sol";
import {MacAppAttestV1} from "../src/MacAppAttestV1.sol";
import {P256Verifier} from "./P256Verifier.sol";
import {AppleAttest} from "../src/AppleAttest.sol";
import {AppleLeaf} from "../src/AppleLeaf.sol";
import {AppleAuthData} from "../src/AppleAuthData.sol";
import {StrictDER as D} from "../src/StrictDER.sol";
import {P384} from "../src/P384.sol";
import {SHA384} from "../src/SHA384.sol";

contract GasStorage is AppleAttest {
    constructor() AppleAttest(new AppleEndorsements(),msg.sender,0,0,false) {}
    function admit(bytes32,bytes32) internal pure override {}
    function write(bytes32 id,uint256 x,uint256 y,uint64 expires) external returns(uint256){uint256 gas=gasleft();keys[id]=Key(x,y,expires,0,true);return gas-gasleft();}
}
abstract contract GasFixture is Test {
    MacAppAttestV1 adapter;bytes cert;bytes auth;bytes clientData;bytes32 kid;string fixture;
    function load(string memory path,uint32 category,bool ios) internal {
        fixture=vm.readFile(path);
        cert=vm.parseJsonBytes(fixture,".cert");auth=vm.parseJsonBytes(fixture,".auth");clientData=vm.parseJsonBytes(fixture,".clientData");kid=vm.parseJsonBytes32(fixture,".kid");
        bytes memory guid=vm.parseJsonBytes(fixture,".aaguid");bytes16 aaguid;assembly{aaguid:=mload(add(guid,32))}
        adapter=new MacAppAttestV1(new AppleEndorsements(),address(this),vm.parseJsonBytes32(fixture,".appHash"),vm.parseJsonBytes32(fixture,".cdhash"),aaguid,category,ios);adapter.endorsements().endorseIntermediate(vm.readFileBinary("fixtures/apple-intermediate.der"));
    }
    function iphone() internal {vm.warp(1790200000);load("fixtures/iphone-apple.json",5,true);}
    function assertion(string memory name) internal view returns(bytes32 context,bytes memory proof){
        context=sha256(vm.parseJsonBytes(fixture,string.concat(".",name,".context")));
        proof=abi.encode(kid,vm.parseJsonBytes(fixture,string.concat(".",name,".auth")),uint256(vm.parseJsonBytes32(fixture,string.concat(".",name,".r"))),uint256(vm.parseJsonBytes32(fixture,string.concat(".",name,".s"))));
    }

}
contract GasBreakdownTest is GasFixture {
    function setUp() public {vm.warp(1789567200);load("fixtures/real-apple.json",3,false);}
    function components(uint32 category) internal {
        bytes memory c=cert;bytes memory a=auth;bytes memory client=clientData;GasStorage store=new GasStorage();
        uint256 gas=gasleft();bytes32 nonce=sha256(abi.encodePacked(a,sha256(client)));
        emit log_named_uint("nonce SHA256 pair",gas-gasleft());
        bytes32 acl=adapter.keyACL();
        gas=gasleft();AppleLeaf.Parsed memory leaf=AppleLeaf.parse(c,0x46204201d1f19bafcf31fc60e9ebfd04be6ff265b93b9ba037196d24095f6c10,nonce,acl);
        emit log_named_uint("AppleLeaf parse including TBS SHA256",gas-gasleft());
        D.Node memory outer=D.expect(c,0,c.length,0x30);D.Node memory tbs=D.expect(c,outer.body,outer.end,0x30);bytes memory encoded=D.encoded(c,tbs);
        gas=gasleft();bytes32 digest=sha256(encoded);uint256 used=gas-gasleft();assertEq(digest,leaf.tbsHash);
        emit log_named_uint("TBS SHA256 only (already copied)",used);
        bytes16 guid=bytes16(vm.parseJsonBytes(fixture,".aaguid"));
        gas=gasleft();(,bytes32 parsedKid,,)=AppleAuthData.check(a,guid,true,leaf.x,leaf.y,category);used=gas-gasleft();assertEq(parsedKid,kid);
        emit log_named_uint("AppleAuthData check",used);
        gas=gasleft();bool ok=P384.verify(0xae5b37a0774d79b2358f40e7d1f22626,0xf1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706,0x9e98d363bd5e370fbfa08e329e8073a9,0x85e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99,uint256(leaf.tbsHash),leaf.rhi,leaf.rlo,leaf.shi,leaf.slo);
        used=gas-gasleft();assertTrue(ok);emit log_named_uint("leaf P384 verify",used);
        used=store.write(kid,leaf.x,leaf.y,leaf.expires);emit log_named_uint("storage assignment (three fresh slots)",used);
    }
    function test_GasMacComponents() public {components(3);}
    function test_GasIPhoneComponents() public {iphone();components(5);}
    function enrollGas() internal {uint256 gas=gasleft();bytes32 id=adapter.enroll(cert,auth,clientData,EF.id());uint256 used=gas-gasleft();assertEq(id,kid);emit log_named_uint("total enroll external call",used);}
    function test_GasMacEnroll() public {enrollGas();}
    function test_GasIPhoneEnroll() public {iphone();enrollGas();}
    function test_GasRootIntermediate() public {
        bytes memory c=vm.readFileBinary("fixtures/apple-intermediate.der");uint256 total=gasleft();
        D.Node memory outer=D.expect(c,0,c.length,0x30);D.Node memory tbs=D.expect(c,outer.body,outer.end,0x30);
        uint256 gas=gasleft();bytes memory encoded=D.encoded(c,tbs);uint256 copyGas=gas-gasleft();
        gas=gasleft();bytes memory digest=SHA384.hash(encoded);uint256 used=gas-gasleft();
        uint256 hashGas=used;
        D.Node memory alg=D.expect(c,tbs.end,outer.end,0x30);D.Node memory bits=D.expect(c,alg.end,outer.end,3);D.Node memory seq=D.expect(c,bits.body+1,bits.end,0x30);
        D.Node memory r=D.expect(c,seq.body,seq.end,2);D.Node memory s=D.expect(c,r.end,seq.end,2);
        (uint256 rh,uint256 rl)=AppleLeaf.scalar(D.integer(c,r,48));(uint256 sh,uint256 sl)=AppleLeaf.scalar(D.integer(c,s,48));
        (uint256 hh,uint256 hl)=AppleLeaf.scalar(digest);
        gas=gasleft();bool ok=rootVerify(hh,hl,rh,rl,sh,sl);used=gas-gasleft();total-=gasleft();assertTrue(ok);
        assertEq(digest,hex"ed64d1076dd3beb0ef3c512fcbb3b734aa6e6c3ac81f32e102ebb283664f8193227ddec3b72a4b7b99213cfacf08ee25");
        emit log_named_uint("intermediate TBS DER copy",copyGas);emit log_named_uint("intermediate SHA384",hashGas);emit log_named_uint("root P384 verify (384-bit digest)",used);emit log_named_uint("root intermediate positive pipeline",total);
        assertFalse(rootVerify(hh,hl^1,rh,rl,sh,sl));
    }
    // P384.verify accepts only a 256-bit digest; the intermediate is SHA384.
    function rootVerify(uint256 hh,uint256 hl,uint256 rh,uint256 rl,uint256 sh,uint256 sl) internal view returns(bool){
        P384.C384Elm memory q=P384.C384Elm(0x4531e198b5b4ec04da1502045704ed4f,0x877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd6,0x56141404702831e43f70b88fd6c394b6,0x08ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35);
        return P384.verify384(q,hh,hl,rh,rl,sh,sl);
    }
}

contract GasAssertionTest is GasFixture {
    function setUp() public {vm.warp(1789588800);load("fixtures/fresh-apple.json",3,false);adapter.enroll(cert,auth,clientData,EF.id());}
    function assertionGas() internal {
        (bytes32 context,bytes memory proof)=assertion("assert");vm.cool(address(adapter));
        uint256 gas=gasleft();bytes32 id=adapter.verify(context,proof);uint256 used=gas-gasleft();assertEq(id,kid);emit log_named_uint("assertion verify external call",used);
    }
    function test_GasAssertionEtchedP256() public {P256Verifier p=new P256Verifier();vm.etch(address(0x100),address(p).code);assertionGas();}
    function test_GasAssertionNativeP256() public {
        if(block.chainid==31337){vm.skip(true);return;}
        assertEq(block.chainid,84532);emit log_named_uint("fork block",block.number);assertionGas();
    }
}
