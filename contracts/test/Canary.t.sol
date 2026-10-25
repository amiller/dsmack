// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {Canary, IAttestVerifier, ICDRegistry} from "../src/Canary.sol";
import {P256Verifier} from "attest-test/P256Verifier.sol";

/// Stands in for AppleAttestRegistryV1 and its CDRegistry: proof = abi.encode(context, cdhash),
/// admitted only while the cdhash's build is the current build.
contract MockAttest is IAttestVerifier, ICDRegistry {
    bytes32 public buildId;
    mapping(bytes32 => bytes32) buildOf;
    function setBuild(bytes32 b) external { buildId = b; }
    function admit(bytes32 cdhash, bytes32 b) external { buildOf[cdhash] = b; }
    function cds() external view returns (ICDRegistry) { return this; }
    function verify(bytes32 context, bytes calldata proof) external view returns (bytes32) {
        (bytes32 signed, bytes32 cdhash) = abi.decode(proof, (bytes32, bytes32));
        require(signed == context, "assertion signature");
        require(buildOf[cdhash] == buildId, "build not admitted");
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
    bytes32 constant RUNNER = keccak256("runner cdhash");
    bytes32 constant PROBE = keccak256("probe cdhash");
    bytes32 constant RESIGNED = keccak256("runner re-signed by another team");
    bytes32 constant RUNNER_BUILD = keccak256("runner build");
    bytes32 constant PROBE_BUILD = keccak256("probe build");
    MockAttest m;

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);  // Base RIP-7212
        m = new MockAttest();
        m.admit(RUNNER, RUNNER_BUILD);
        m.admit(RESIGNED, RUNNER_BUILD);
        m.admit(PROBE, PROBE_BUILD);
        m.setBuild(RUNNER_BUILD);
        c = new Canary(m);
        vm.deal(address(this), 10 ether);
    }

    function events(string memory canary, bool late) internal view returns (Canary.Event[] memory ev) {
        (uint256 x, uint256 y) = vm.publicKeyP256(CANARY_KEY);
        ev = new Canary.Event[](late ? 4 : 3);
        ev[0] = Canary.Event("services", "worker");
        ev[1] = Canary.Event(canary, abi.encodePacked(x, y));
        ev[2] = Canary.Event("system-ready", "");
        if (late) ev[3] = Canary.Event("late", "");
    }

    function head(Canary.Event[] memory ev) internal pure returns (bytes32 h) {
        for (uint256 i; i < ev.length; i++) {
            bytes memory n = bytes(ev[i].name);
            h = sha256(abi.encodePacked(h, sha256(abi.encodePacked(uint32(n.length), n, uint32(ev[i].payload.length), ev[i].payload))));
        }
    }

    /// A guest Attest assertion by `cdhash` over `ev` for (image, manifest), claimed for `to` with
    /// the canary key's signature for `signedFor`; `err` is the expected revert, if any.
    function claim(uint256 id, address payable to, address signedFor, bytes32 image, bytes32 manifest,
                   Canary.Event[] memory ev, bytes32 cdhash, bytes memory err) internal {
        Canary.Attested memory a = Canary.Attested(image, manifest, keccak256("run"), sha256("worker"), new bytes(64));
        bytes32 ctx = sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", image, manifest, a.run, head(ev), a.caller, a.reportData));
        (bytes32 r, bytes32 s) = vm.signP256(CANARY_KEY, c.claimDigest(id, signedFor));
        if (err.length > 0) vm.expectRevert(err);
        c.claimKey(id, to, a, ev, abi.encode(ctx, cdhash), r, s);
    }

    function test_forgeryPaysOnceToBoundClaimant() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, RUNNER_BUILD, 0, 0, uint64(block.timestamp + 30 days));
        bytes memory proof = abi.encode(c.forgeryContext(id, alice), RUNNER);
        // A front-runner cannot redirect the payout: the assertion is over alice's address.
        vm.expectRevert("assertion signature");
        c.claimForgery(id, bob, proof);
        c.claimForgery(id, alice, proof);
        assertEq(alice.balance, 1 ether);
        (,,,,,,, bool burned) = c.entries(id);
        assertTrue(burned && c.burnedBuild(RUNNER_BUILD));
        vm.expectRevert("burned");
        c.claimForgery(id, alice, proof);
    }

    function test_ownerCanaryBindsImageManifestAndClaimant() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Owner, RUNNER_BUILD, IMAGE, MANIFEST, uint64(block.timestamp + 30 days));
        Canary.Event[] memory ev = events("canary-guest-key", false);
        // A run of another image (e.g. one the owner built to leak its key) or another workload does not pay.
        claim(id, alice, alice, keccak256("owner image"), MANIFEST, ev, RUNNER, "not this canary");
        claim(id, alice, alice, IMAGE, keccak256("leaky compose"), ev, RUNNER, "not this canary");
        // The canary key signed alice, so the same signature cannot pay bob.
        claim(id, bob, alice, IMAGE, MANIFEST, ev, RUNNER, "canary signature");
        claim(id, alice, alice, IMAGE, MANIFEST, ev, RUNNER, "");
        assertEq(alice.balance, 1 ether);
        assertTrue(c.burnedImage(IMAGE) && !c.burnedBuild(RUNNER_BUILD));
    }

    /// The supervisor seals before any workload exists and the app refuses events after the seal, so
    /// an event after system-ready could only come from a workload; such a log does not pay.
    function test_eventAfterSystemReadyDoesNotPay() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Guest, RUNNER_BUILD, IMAGE, 0, uint64(block.timestamp + 30 days));
        claim(id, alice, alice, IMAGE, MANIFEST, events("canary-guest-key", true), RUNNER, "system-ready last");
    }

    /// Runner entries admit any image, whose own supervisor knows its guest key; only the app's event pays them.
    function test_guestKeyDoesNotPayRunnerEntry() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Runner, RUNNER_BUILD, 0, 0, uint64(block.timestamp + 30 days));
        claim(id, alice, alice, keccak256("any image"), MANIFEST, events("canary-guest-key", false), RUNNER, "canary event");
        claim(id, alice, alice, keccak256("any image"), MANIFEST, events("canary-runner-key", false), RUNNER, "");
        assertTrue(c.burnedBuild(RUNNER_BUILD));
    }

    /// The App Attest probe asserts any file it is given, so its assertions must not pay a runner canary.
    function test_keyAssertionFromAnotherBuildDoesNotPay() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Guest, RUNNER_BUILD, IMAGE, 0, uint64(block.timestamp + 30 days));
        m.setBuild(PROBE_BUILD);
        claim(id, alice, alice, IMAGE, MANIFEST, events("canary-guest-key", false), PROBE, "build");
    }

    /// The App Attest probe asserts any file it is given, so its assertions must not pay a runner canary.
    function test_forgeryFromAnotherBuildDoesNotPay() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, RUNNER_BUILD, 0, 0, uint64(block.timestamp + 30 days));
        bytes memory proof = abi.encode(c.forgeryContext(id, alice), PROBE);
        m.setBuild(PROBE_BUILD);
        vm.expectRevert("build");
        c.claimForgery(id, alice, proof);
    }

    /// The approved runner is signed for one device; anyone else attacks a copy re-signed by their own team.
    function test_reSignedRunnerCanClaim() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Runner, RUNNER_BUILD, 0, 0, uint64(block.timestamp + 30 days));
        claim(id, alice, alice, keccak256("any image"), MANIFEST, events("canary-runner-key", false), RESIGNED, "");
        assertEq(alice.balance, 1 ether);
    }

    function test_guestCanaryRequiresImage() public {
        vm.expectRevert("unbound image");
        c.arm{value: 1 ether}(Canary.Kind.Guest, RUNNER_BUILD, 0, 0, uint64(block.timestamp + 30 days));
    }

    function test_reclaimOnlyAfterExpiry() public {
        uint256 id = c.arm{value: 1 ether}(Canary.Kind.Forgery, RUNNER_BUILD, 0, 0, uint64(block.timestamp + 30 days));
        vm.expectRevert("reclaim");
        c.reclaim(id);
        vm.warp(block.timestamp + 31 days);
        c.reclaim(id);
        assertEq(address(this).balance, 10 ether);
    }

    receive() external payable {}
}
