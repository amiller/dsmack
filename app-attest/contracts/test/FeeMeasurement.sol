// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test,console} from "forge-std/Test.sol";
interface GasPriceOracle {function getL1Fee(bytes memory) external view returns(uint256);}
abstract contract FeeMeasurement is Test {
    function rlp(bytes memory b,bool list) internal pure returns(bytes memory){
        if(!list && b.length==1 && uint8(b[0])<128)return b;
        uint256 offset=list?192:128;
        if(b.length<56)return abi.encodePacked(bytes1(uint8(offset+b.length)),b);
        require(b.length<=65535,"RLP size");
        if(b.length<256)return abi.encodePacked(bytes1(uint8(offset+56)),bytes1(uint8(b.length)),b);
        return abi.encodePacked(bytes1(uint8(offset+57)),bytes2(uint16(b.length)),b);
    }
    function number(uint256 n) internal pure returns(bytes memory){
        if(n==0)return hex"80";
        bytes memory b;while(n!=0){b=abi.encodePacked(bytes1(uint8(n)),b);n>>=8;}return rlp(b,false);
    }
    function fees(address target,bytes memory data,uint256 gas) internal view {
        uint256 intrinsic=21000;for(uint256 i;i<data.length;i++)intrinsic+=data[i]==0?4:16;
        console.log("callee execution gas",gas);console.log("calldata bytes",data.length);console.log("intrinsic gas",intrinsic);console.log("transaction gas",gas+intrinsic);
        if(block.chainid==31337)return;
        // Unsigned EIP-1559 transaction, nonce 0, 1M wei tip, no value/access list; oracle adds signature allowance.
        bytes memory body=abi.encodePacked(number(block.chainid),hex"80",number(1000000),number(6000000),number(16777216),rlp(abi.encodePacked(target),false),hex"80",rlp(data,false),hex"c0");
        bytes memory txdata=abi.encodePacked(hex"02",rlp(body,true));
        console.log("fork chain",block.chainid);console.log("fork block",block.number);
        console.log("L1 actual calldata fee wei",GasPriceOracle(0x420000000000000000000000000000000000000F).getL1Fee(data));
        console.log("unsigned transaction bytes",txdata.length);
        console.log("L1 unsigned transaction fee wei",GasPriceOracle(0x420000000000000000000000000000000000000F).getL1Fee(txdata));
    }
}
