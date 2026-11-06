// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import "../src/PageBundleRegistry.sol";

contract PageBundleRegistryTest is Test {
    PageBundleRegistry registry;
    string constant FIRST = "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    string constant SECOND = "bafkreibbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    function setUp() public { registry = new PageBundleRegistry(address(this)); }
    function testPublishAndReplace() public {
        registry.publish(FIRST);
        assertEq(registry.latestCID(), FIRST);
        registry.publish(SECOND);
        assertEq(registry.latestCID(), SECOND);
    }
    function testOnlyPublisher() public {
        vm.prank(address(1)); vm.expectRevert("publisher only"); registry.publish(FIRST);
        assertEq(registry.latestCID(), "");
    }
    function testRejectInvalidCID() public {
        vm.expectRevert("raw CID required"); registry.publish("not-a-cid");
    }
}
