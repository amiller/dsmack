// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {AppleEndorsements} from "../src/AppleEndorsements.sol";
import {P384} from "../src/P384.sol";
library EndorsementFixture {
    function key() internal pure returns(uint128[6] memory){return [uint128(0xae5b37a0774d79b2358f40e7d1f22626),uint128(0xf1c25fef17802deab3826a59874ff8d2),uint128(0xad1525789aa26604191248b63cb96706),uint128(0x9e98d363bd5e370fbfa08e329e8073a9),uint128(0x85e7746ea359a2f66f29db32af455e21),uint128(0x1658d567af9e267eb2614dc21a66ce99)];}
    function id() internal pure returns(bytes32){return 0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90;}
}
contract RotationEndorsements is AppleEndorsements {
    function _rootKey() internal pure override returns(P384.C384Elm memory){
        return P384.C384Elm(0x283c1d7365ce4788f29f8ebf234edffe,0xad6fe997fbea5ffa2d58cc9dfa7b1c508b05526f55b9ebb2040f05b48fb6d0e1,0x9475c99061e41b88ba52efdb8c169047,0x1a61d867ed799729d9c92cd01dbd225630d84ede32a78f9e64664cdac512ef8c);
    }
}
