// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {Canary, IAttestVerifier} from "../src/Canary.sol";

/// Stands in for AppleAttestRegistryV1: proof = abi.encode(context, cdhash of the asserting build).
contract MockAttest is IAttestVerifier {
    mapping(bytes32 => bytes32) cdhashOf;
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32) {
        (bytes32 signed, bytes32 cdhash) = abi.decode(proof, (bytes32, bytes32));
        require(signed == context, "assertion signature");
        cdhashOf[context] = cdhash;
        return context;
    }
    function assertionEvidence(bytes32 kid) external view returns (bytes32, bytes32, bytes32, uint64, uint32) {
        return (kid, cdhashOf[kid], 0, 0, 0);
    }
}

contract CanaryTest is Test {
    Canary c;
    address payable alice = payable(address(0xA11CE));
    address payable bob = payable(address(0xB0B));
    uint256 constant CANARY_KEY = 0xC0FFEE;
    bytes32 constant IMAGE = keccak256("canary image");
    bytes32 constant MANIFEST = keccak256("sleep compose");
    bytes32 constant RUNNER = keccak256("runner cdhash");
    bytes32 constant PROBE = keccak256("probe cdhash");

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
        bytes memory proof = abi.encode(c.keyContext(Canary.Kind.Guest, image, MANIFEST, key), RUNNER);
        (uint8 v, bytes32 r, bytes32 s) = sign(id, to);
        if (err.length > 0) vm.expectRevert(err);
        c.claimKey(id, to, image, MANIFEST, key, proof, v, r, s);
    }

    function test_forgeryPaysOnceToBoundClaimant() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, RUNNER, 0, 0, uint64(block.timestamp + 30 days));
        bytes memory proof = abi.encode(c.forgeryContext(id, alice), RUNNER);
        // A front-runner cannot redirect the payout: the assertion is over alice's address.
        vm.expectRevert("assertion signature");
        c.claimForgery(id, bob, proof);
        c.claimForgery(id, alice, proof);
        assertEq(alice.balance, 1 ether);
        (,,,,,,, bool burned) = c.entries(id);
        assertTrue(burned);
        vm.expectRevert("burned");
        c.claimForgery(id, alice, proof);
    }

    function test_keyCanaryBindsImageAndClaimant() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Guest, RUNNER, IMAGE, 0, uint64(block.timestamp + 30 days));
        // A run of another image (e.g. one the owner built to leak its key) does not pay.
        claimGuest(id, alice, keccak256("owner image"), "not this canary");
        // The canary key signed alice, so the same signature cannot pay bob.
        address key = vm.addr(CANARY_KEY);
        bytes memory proof = abi.encode(c.keyContext(Canary.Kind.Guest, IMAGE, MANIFEST, key), RUNNER);
        (uint8 v, bytes32 r, bytes32 s) = sign(id, alice);
        vm.expectRevert("canary signature");
        c.claimKey(id, bob, IMAGE, MANIFEST, key, proof, v, r, s);
        claimGuest(id, alice, IMAGE, "");
        assertEq(alice.balance, 1 ether);
    }

    function test_keyAssertedForOtherKindDoesNotPay() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Owner, RUNNER, IMAGE, MANIFEST, uint64(block.timestamp + 30 days));
        claimGuest(id, alice, IMAGE, "assertion signature");
    }

    /// The App Attest probe asserts any file it is given, so its assertions must not pay a runner canary.
    function test_forgeryFromAnotherBuildDoesNotPay() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, RUNNER, 0, 0, uint64(block.timestamp + 30 days));
        bytes memory proof = abi.encode(c.forgeryContext(id, alice), PROBE);
        vm.expectRevert("build");
        c.claimForgery(id, alice, proof);
    }

    function test_guestCanaryRequiresImage() public {
        vm.expectRevert("unbound image");
        c.arm{value: 1 ether}(Canary.Kind.Guest, RUNNER, 0, 0, uint64(block.timestamp + 30 days));
    }

    function test_reclaimOnlyAfterExpiry() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, RUNNER, 0, 0, uint64(block.timestamp + 30 days));
        vm.expectRevert("reclaim");
        c.reclaim(id);
        vm.warp(block.timestamp + 31 days);
        c.reclaim(id);
        assertEq(address(this).balance, 10 ether);
    }

    receive() external payable {}
}
