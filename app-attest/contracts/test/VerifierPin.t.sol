// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";

contract VerifierPinTest is Test {
    function test_VerifierPin() public view {
        string memory base="../circuit/verifier/";
        string memory pin=vm.readFile(string.concat(base,"pin.json"));
        bytes32 vk=vm.parseJsonBytes32(pin,".vk_sha256");
        assertEq(sha256(vm.readFileBinary(string.concat(base,"vk"))),vk);
        assertEq(sha256(bytes(vm.readFile(string.concat(base,"HonkVerifierLeaf.sol")))),vm.parseJsonBytes32(pin,".verifier_sha256"));
    }
}
