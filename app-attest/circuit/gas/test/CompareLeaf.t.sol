// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {Test,console} from "forge-std/Test.sol";
import {HonkVerifier as Leaf} from "leaf-verifier/HonkVerifierLeaf.sol";

interface Verifier {function verify(bytes calldata,bytes32[] calldata) external view returns(bool);}

contract CompareLeafTest is Test {
    function check(string memory variant,string memory profile,Verifier v,uint256 count) internal {
        string memory dir=string.concat("../proofs/",variant,"/",profile,"/");
        bytes memory proof=vm.readFileBinary(string.concat(dir,"proof"));
        bytes memory raw=vm.readFileBinary(string.concat(dir,"public_inputs"));
        require(raw.length==count*32);
        bytes32[] memory inputs=new bytes32[](count);
        for(uint256 i;i<count;i++){
            bytes32 word;
            assembly{word:=mload(add(add(raw,32),mul(i,32)))}
            inputs[i]=word;
        }
        uint256 start=gasleft();require(v.verify(proof,inputs));
        console.log(string.concat(variant," ",profile," external call gas"),start-gasleft());
        for(uint256 i;i<count;i++){
            inputs[i]=bytes32(uint256(inputs[i])^1);
            vm.expectRevert();v.verify(proof,inputs);
            inputs[i]=bytes32(uint256(inputs[i])^1);
        }
        proof[100]=bytes1(uint8(proof[100])^1);
        vm.expectRevert();v.verify(proof,inputs);
    }
    function test_leafMac() public {check("leaf","mac",Verifier(address(new Leaf())),24);}
    function test_leafIphone() public {check("leaf","iphone",Verifier(address(new Leaf())),24);}
}
