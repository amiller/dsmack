// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {Canary, IAttestVerifier} from "../src/Canary.sol";

/// Stands in for AppleAttestRegistryV1: a proof is valid for exactly the context it encodes.
contract MockAttest is IAttestVerifier {
    function verify(bytes32 context, bytes calldata proof) external pure returns (bytes32) {
        require(abi.decode(proof, (bytes32)) == context, "assertion signature");
        return context;
    }
}

contract CanaryTest is Test {
    Canary c;
    address payable alice = payable(address(0xA11CE));
    address payable bob = payable(address(0xB0B));
    uint256 constant CANARY_KEY = 0xC0FFEE;
    bytes32 constant IMAGE = keccak256("canary image");
    bytes32 constant MANIFEST = keccak256("sleep compose");

    function setUp() public {
        c = new Canary(new MockAttest());
        vm.deal(address(this), 10 ether);
    }

    function sign(uint256 id, address claimant) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        return vm.sign(CANARY_KEY, c.claimDigest(id, claimant));
    }

    /// Claims with a Guest-kind assertion for `image`; `err` is the expected revert, if any.
    function claimGuest(uint256 id, address payable to, bytes32 image, bytes memory err) internal {
        address key = vm.addr(CANARY_KEY);
        bytes memory proof = abi.encode(c.keyContext(Canary.Kind.Guest, image, MANIFEST, key));
        (uint8 v, bytes32 r, bytes32 s) = sign(id, to);
        if (err.length > 0) vm.expectRevert(err);
        c.claimKey(id, to, image, MANIFEST, key, proof, v, r, s);
    }

    function test_forgeryPaysOnceToBoundClaimant() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, 0, 0, uint64(block.timestamp + 30 days));
        bytes memory proof = abi.encode(c.forgeryContext(id, alice));
        // A front-runner cannot redirect the payout: the assertion is over alice's address.
        vm.expectRevert("assertion signature");
        c.claimForgery(id, bob, proof);
        c.claimForgery(id, alice, proof);
        assertEq(alice.balance, 1 ether);
        (,,,,,, bool burned) = c.entries(id);
        assertTrue(burned);
        vm.expectRevert("burned");
        c.claimForgery(id, alice, proof);
    }

    function test_keyCanaryBindsImageAndClaimant() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Guest, IMAGE, 0, uint64(block.timestamp + 30 days));
        // A run of another image (e.g. one the owner built to leak its key) does not pay.
        claimGuest(id, alice, keccak256("owner image"), "not this canary");
        // The canary key signed alice, so the same signature cannot pay bob.
        address key = vm.addr(CANARY_KEY);
        bytes memory proof = abi.encode(c.keyContext(Canary.Kind.Guest, IMAGE, MANIFEST, key));
        (uint8 v, bytes32 r, bytes32 s) = sign(id, alice);
        vm.expectRevert("canary signature");
        c.claimKey(id, bob, IMAGE, MANIFEST, key, proof, v, r, s);
        claimGuest(id, alice, IMAGE, "");
        assertEq(alice.balance, 1 ether);
    }

    function test_keyAssertedForOtherKindDoesNotPay() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Owner, IMAGE, MANIFEST, uint64(block.timestamp + 30 days));
        claimGuest(id, alice, IMAGE, "assertion signature");
    }

    function test_reclaimOnlyAfterExpiry() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, 0, 0, uint64(block.timestamp + 30 days));
        vm.expectRevert("reclaim");
        c.reclaim(id);
        vm.warp(block.timestamp + 31 days);
        c.reclaim(id);
        assertEq(address(this).balance, 10 ether);
    }

    receive() external payable {}
}
