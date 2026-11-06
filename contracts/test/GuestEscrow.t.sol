// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {GuestEscrow, IGuestAttest} from "../src/GuestEscrow.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {EndorsementFixture as EF} from "attest-test/EndorsementFixture.sol";
import {P256Verifier} from "attest-test/P256Verifier.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";
import {CDRegistry} from "../src/CDRegistry.sol";

/// Stands in for AppleAttestRegistryV1: proof = abi.encode(context, cdhash).
contract MockGuestAttest is IGuestAttest {
    address public immutable registry;
    mapping(bytes32 => bytes32) evidence;
    constructor(address r) { registry = r; }
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32 kid) {
        require(msg.sender == registry, "registry only");
        (bytes32 signed, bytes32 cdhash) = abi.decode(proof, (bytes32, bytes32));
        require(signed == context, "assertion signature");
        kid = keccak256(abi.encode(cdhash));
        evidence[kid] = cdhash;
    }
    function assertionEvidence(bytes32 kid) external view returns (bytes32, bytes32, bytes32, uint64, uint32) {
        return (0, evidence[kid], 0, 0, 0);
    }
}

contract GuestEscrowBase is Test {
    GuestEscrow esc;
    LayoverCredit token;
    address buyer = address(0xB1);
    address operator = address(0x22);
    address other = address(0x33);
    uint256 guestKey = 0x6E57;
    uint256 guestKey2 = 0x6E58;
    bytes32 termsHash = keccak256("terms");
    bytes32 constant IMAGE = keccak256("layover image");
    bytes32 constant MANIFEST = keccak256("layover manifest");
    bytes32 CALLER = sha256("agent");
    bytes32 constant CDHASH = keccak256("runner cdhash");

    function deploy(IGuestAttest attest) internal {
        token = new LayoverCredit(address(this), 1_000_000e6);
        esc = new GuestEscrow(address(token), address(this), attest);
        esc.setWorkload(IMAGE, MANIFEST, CALLER, true);
    }
    function events() internal pure returns (GuestEscrow.Event[] memory ev) {
        ev = new GuestEscrow.Event[](2);
        ev[0] = GuestEscrow.Event("services", "agent");
        ev[1] = GuestEscrow.Event("system-ready", "");
    }
    function attested() internal view returns (GuestEscrow.Attested memory) {
        return GuestEscrow.Attested(IMAGE, MANIFEST, keccak256("run"), CALLER);
    }
    function context(GuestEscrow.Attested memory a, address key, address op) internal view returns (bytes32) {
        return sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", a.image, a.manifest, a.run, esc.eventHead(events()), a.caller, abi.encode(key, op)));
    }
}

contract GuestEscrowTest is GuestEscrowBase {
    MockGuestAttest m;

    function setUp() public {
        vm.warp(30 weeks);
        m = new MockGuestAttest(vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 2));
        deploy(m);
        token.transfer(buyer, 100e6);
        vm.startPrank(buyer);
        token.approve(address(esc), 50e6); esc.deposit(50e6);
        esc.acceptTerms(termsHash, operator, 10e6);
        vm.stopPrank();
    }
    function register(uint256 key, address op) internal { register(key, op, ""); }
    function register(uint256 key, address op, bytes memory err) internal {
        GuestEscrow.Attested memory a = attested();
        bytes memory p = abi.encode(context(a, vm.addr(key), op), CDHASH);
        if (err.length > 0) vm.expectRevert(err);
        esc.registerGuestKey(vm.addr(key), op, a, events(), p);
    }
    function sig(uint256 key, address op, uint256 owed, uint64 period) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, esc.claimDigest(buyer, op, termsHash, owed, period));
        return abi.encodePacked(r, s, v);
    }
    function claim(uint256 key, uint256 owed) internal { claim(key, owed, ""); }
    function claim(uint256 key, uint256 owed, bytes memory err) internal {
        bytes memory g = sig(key, operator, owed, 30);
        if (err.length > 0) vm.expectRevert(err);
        esc.claim(buyer, termsHash, owed, 30, g);
    }

    function testConstructorRequiresVerifierBoundToEscrow() public {
        MockGuestAttest wrong = new MockGuestAttest(address(0xdead));
        vm.expectRevert("attest registry");
        new GuestEscrow(address(token), address(this), wrong);
    }
    function testRegisteredGuestClaimPays() public {
        register(guestKey, operator);
        (address op, bytes32 w, bytes32 kid, bytes32 cd) = esc.guestKeys(vm.addr(guestKey));
        assertEq(op, operator); assertEq(w, esc.workloadId(IMAGE, MANIFEST, CALLER)); assertEq(cd, CDHASH); assertEq(kid, keccak256(abi.encode(CDHASH)));
        claim(guestKey, 3e6);
        claim(guestKey, 4e6);
        assertEq(token.balanceOf(operator), 4e6);
        assertEq(esc.balance(buyer), 46e6);
        assertEq(esc.totalClaimed(buyer, termsHash), 4e6);
    }
    function testUnregisteredKeyRefused() public {
        claim(guestKey, 1e6, "guest key not registered");
    }
    function testWrongOperatorRefused() public {
        register(guestKey, other);
        // Signed for the terms' operator, but the key belongs to another operator.
        claim(guestKey, 1e6, "terms operator");
    }
    function testOverCapRefused() public {
        register(guestKey, operator);
        register(guestKey2, operator);
        claim(guestKey, 10e6 + 1, "terms cap");
        claim(guestKey, 6e6);
        // Each key keeps its own cumulative; together they stay within the cap.
        claim(guestKey2, 5e6, "terms cap");
        claim(guestKey2, 4e6);
        assertEq(token.balanceOf(operator), 10e6);
    }
    function testReplayRefused() public {
        register(guestKey, operator);
        claim(guestKey, 2e6);
        claim(guestKey, 2e6, "claim replay");
        claim(guestKey, 1e6, "claim replay");
    }
    function testKeyFromUnapprovedBuildRefused() public {
        register(guestKey, operator);
        claim(guestKey, 1e6);
        esc.setWorkload(IMAGE, MANIFEST, CALLER, false);
        claim(guestKey, 2e6, "build not approved");
        // Registration from an unapproved build is refused too.
        register(guestKey2, operator, "build not approved");
        // Another service in the approved workload is a different build entry.
        esc.setWorkload(IMAGE, MANIFEST, CALLER, true);
        CALLER = sha256("gateway");
        register(guestKey2, operator, "build not approved");
    }
    function testReportDataBindsKeyAndOperator() public {
        GuestEscrow.Attested memory a = attested();
        bytes memory proof = abi.encode(context(a, vm.addr(guestKey), operator), CDHASH);
        // A relayer cannot re-bind the honest guest's assertion to another operator or key.
        vm.expectRevert("assertion signature");
        esc.registerGuestKey(vm.addr(guestKey), other, a, events(), proof);
        vm.expectRevert("assertion signature");
        esc.registerGuestKey(vm.addr(guestKey2), operator, a, events(), proof);
        esc.registerGuestKey(vm.addr(guestKey), operator, a, events(), proof);
        vm.expectRevert("key registered");
        esc.registerGuestKey(vm.addr(guestKey), operator, a, events(), proof);
    }
    function testEventLogMustEndInSystemReady() public {
        GuestEscrow.Event[] memory ev = new GuestEscrow.Event[](2);
        ev[0] = GuestEscrow.Event("system-ready", "");
        ev[1] = GuestEscrow.Event("late", "");
        vm.expectRevert("system-ready last");
        esc.registerGuestKey(vm.addr(guestKey), operator, attested(), ev, "");
    }
    function testWorkloadOwnerOnly() public {
        vm.prank(other);
        vm.expectRevert("owner only");
        esc.setWorkload(IMAGE, MANIFEST, CALLER, true);
    }
    function testUnacceptedTermsAndDepositLimit() public {
        register(guestKey, operator);
        bytes memory g = sig(guestKey, operator, 1e6, 30);
        vm.expectRevert("terms not accepted");
        esc.claim(other, termsHash, 1e6, 30, g);
        vm.prank(other); esc.acceptTerms(termsHash, operator, 10e6);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guestKey, esc.claimDigest(other, operator, termsHash, 1e6, 30));
        vm.expectRevert("deposit exceeded");
        esc.claim(other, termsHash, 1e6, 30, abi.encodePacked(r, s, v));
    }
    function testSignatureBoundToBuyer() public {
        register(guestKey, operator);
        vm.prank(other); esc.acceptTerms(termsHash, operator, 10e6);
        // buyer's claim signature, replayed for another account, recovers to a different (unregistered) key.
        bytes memory g = sig(guestKey, operator, 1e6, 30);
        vm.expectRevert("guest key not registered");
        esc.claim(other, termsHash, 1e6, 30, g);
    }
    function testExitWindowStopsClaims() public {
        register(guestKey, operator);
        vm.prank(buyer); esc.requestExit();
        claim(guestKey, 1e6);
        vm.warp(block.timestamp + 14 days);
        claim(guestKey, 2e6, "account exited");
        vm.prank(buyer); esc.withdraw();
        assertEq(token.balanceOf(buyer), 99e6);
    }
    function testDepositWithAuthorization() public {
        uint256 payerKey = 0xA11CE;
        address payer = vm.addr(payerKey);
        token.transfer(payer, 5e6);
        bytes32 nonce = keccak256("x402");
        bytes32 h = keccak256(abi.encode(token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), payer, address(esc), 5e6, 0, block.timestamp + 1 hours, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerKey, keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), h)));
        esc.depositWithAuthorization(payer, 5e6, 0, block.timestamp + 1 hours, nonce, abi.encodePacked(r, s, v));
        assertEq(esc.balance(payer), 5e6);
        vm.expectRevert("authorization used");
        esc.depositWithAuthorization(payer, 5e6, 0, block.timestamp + 1 hours, nonce, abi.encodePacked(r, s, v));
    }
}

/// The real verifier and the repo's real App Attest captures: none of them asserted a guest key, so every
/// registration here must fail at the verifier.
contract GuestEscrowRealAttestTest is GuestEscrowBase {
    AppleAttestRegistryV1 adapter;
    string fixture;
    bytes32 kid;

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        vm.warp(1789588800);
        fixture = vm.readFile("../app-attest/contracts/fixtures/fresh-apple.json");
        bytes memory guid = vm.parseJsonBytes(fixture, ".aaguid");
        bytes16 aaguid = bytes16(guid);
        string memory b = vm.readFile("fixtures/cd-args-probe-macos.json");
        CDRegistry cds = new CDRegistry();
        cds.setBuild(vm.parseJsonBytes(b, ".cd"), vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"));
        cds.registerBuild(vm.parseJsonBytes(b, ".cd"), vm.parseJsonBytes(b, ".page0"), vm.parseJsonBytes(b, ".ent"));
        AppleEndorsements e = new AppleEndorsements();
        e.endorseIntermediate(vm.readFileBinary("../app-attest/contracts/fixtures/apple-intermediate.der"));
        // The verifier is deployed first, naming the escrow's address (two creations later) as its only caller.
        adapter = new AppleAttestRegistryV1(e, vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 2), cds, aaguid, 3, false);
        deploy(IGuestAttest(address(adapter)));
        kid = vm.parseJsonBytes32(fixture, ".kid");
        assertEq(adapter.enroll(vm.parseJsonBytes(fixture, ".cert"), vm.parseJsonBytes(fixture, ".auth"), vm.parseJsonBytes(fixture, ".clientData"), EF.id()), kid);
    }
    function proof(string memory name) internal view returns (bytes memory) {
        return abi.encode(kid, vm.parseJsonBytes(fixture, string.concat(".", name, ".auth")),
            uint256(vm.parseJsonBytes32(fixture, string.concat(".", name, ".r"))), uint256(vm.parseJsonBytes32(fixture, string.concat(".", name, ".s"))));
    }
    /// A genuine assertion by an enrolled Mac, over a context other than this guest key's: forged binding.
    function testForgedAssertionRefused() public {
        vm.expectRevert("assertion signature");
        esc.registerGuestKey(vm.addr(guestKey), operator, attested(), events(), proof("assert"));
    }
    /// An assertion older than one the verifier already accepted from that Mac (counter 3 > 1): stale.
    function testStaleAssertionRefused() public {
        (bytes32 ctx, bytes memory restored) = (sha256(vm.parseJsonBytes(fixture, ".restored.context")), proof("restored"));
        vm.prank(address(esc));
        adapter.verify(ctx, restored);
        vm.expectRevert("assertion replay");
        esc.registerGuestKey(vm.addr(guestKey), operator, attested(), events(), proof("assert"));
    }
    /// The Mac's key past its enrollment expiry.
    function testExpiredEnrollmentRefused() public {
        (,, uint64 expires,,) = adapter.keys(kid);
        vm.warp(uint256(expires) + 1);
        vm.expectRevert("key validity");
        esc.registerGuestKey(vm.addr(guestKey), operator, attested(), events(), proof("assert"));
    }
    /// Only the escrow may drive this verifier, so nobody can burn a Mac's assertion counter through it directly.
    function testVerifierBoundToEscrow() public {
        vm.expectRevert("registry only");
        adapter.verify(bytes32(0), proof("assert"));
    }
}
