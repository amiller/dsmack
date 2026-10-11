// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {P384} from "../src/P384.sol";
contract P384JacobianTest is Test {
 function test_IndependentBigIntegerVectors() public {
  string memory f=vm.readFile("fixtures/p384-joint.json");
  for(uint256 i;i<24;i++){
   uint256[8] memory v;
   for(uint256 j;j<8;j++)v[j]=vm.parseUint(vm.parseJsonString(f,string.concat("[",vm.toString(i),"][",vm.toString(j),"]")));
   P384.C384Elm memory g=P384.C384Elm(0xaa87ca22be8b05378eb1c71ef320ad74,0x6e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,0x3617de4a96262c6f5d9e98bf9292dc29,0xf8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f);
   P384.C384Elm memory q=P384.C384Elm(0xae5b37a0774d79b2358f40e7d1f22626,0xf1c25fef17802deab3826a59874ff8d2ad1525789aa26604191248b63cb96706,0x9e98d363bd5e370fbfa08e329e8073a9,0x85e7746ea359a2f66f29db32af455e211658d567af9e267eb2614dc21a66ce99);
   P384.C384Elm memory r=P384.joint(g,q,v[0],v[1],v[2],v[3]);
   assertEq(r.xhi,v[4]);assertEq(r.xlo,v[5]);assertEq(r.yhi,v[6]);assertEq(r.ylo,v[7]);
  }
 }
}
