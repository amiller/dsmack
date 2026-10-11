// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {Network} from "../script/Network.s.sol";
import {DemoV1} from "../src/application/DemoV1.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";
import {P256Verifier} from "./P256Verifier.sol";
contract NetworkTest is Test {
    DemoV1 demo;AppleAttestRegistryV1 ios;AppleAttestRegistryV1 mac;
    function setUp() public {
        P256Verifier p=new P256Verifier();vm.etch(address(0x100),address(p).code);
        vm.setEnv("PRIVATE_KEY","0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        vm.setEnv("MAC_BUILD","fixtures/cd-args-probe-macos.json");vm.setEnv("DEPLOY_OUT","network/deploy-test.json");
        (demo,ios,mac)=new Network().run();
    }
    function enroll(AppleAttestRegistryV1 a,string memory f) internal returns(bytes32 kid,string memory j){
        j=vm.readFile(f);kid=a.enroll(vm.parseJsonBytes(j,".cert"),vm.parseJsonBytes(j,".auth"),vm.parseJsonBytes(j,".clientData"));
        assertEq(kid,vm.parseJsonBytes32(j,".kid"));
    }
    function verify(AppleAttestRegistryV1 a,bytes32 kid,string memory j) internal returns(bytes32){
        bytes32 context=sha256(vm.parseJsonBytes(j,".assert.context"));
        bytes memory proof=abi.encode(kid,vm.parseJsonBytes(j,".assert.auth"),uint256(vm.parseJsonBytes32(j,".assert.r")),uint256(vm.parseJsonBytes32(j,".assert.s")));
        vm.prank(address(demo));return a.verify(context,proof);
    }
    function test_Deployment() public view {
        assertFalse(demo.paused());assertEq(demo.owner(),ios.cds().owner());assertEq(ios.registry(),address(demo));assertEq(mac.registry(),address(demo));
        assertTrue(ios.cds().isAdmitted(0x5395bf39ecded47ab804eb78b7f878c246baa4860ca32cad1c63ed468783b591));
        assertTrue(mac.cds().isAdmitted(0x67dfc08f0eca771ae2787870ab3bffc7dfb39a7fac4db6b0c087e58c2f488d70));
    }
    function test_IPhoneOnIOSAdapter() public {
        vm.warp(1790200000);(bytes32 kid,string memory j)=enroll(ios,"fixtures/iphone-apple.json");assertEq(verify(ios,kid,j),kid);
    }
    function test_MacOnMacAdapter() public {
        vm.warp(1789588800);(bytes32 kid,string memory j)=enroll(mac,"fixtures/fresh-apple.json");assertEq(verify(mac,kid,j),kid);
    }
    function test_IPhoneOnMacAdapterRejected() public {
        vm.warp(1790200000);string memory j=vm.readFile("fixtures/iphone-apple.json");
        vm.expectRevert("key ACL");mac.enroll(vm.parseJsonBytes(j,".cert"),vm.parseJsonBytes(j,".auth"),vm.parseJsonBytes(j,".clientData"));
    }
}
