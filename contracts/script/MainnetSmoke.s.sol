// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {GuestEscrow, IGuestAttest} from "../src/GuestEscrow.sol";
import {MockGuestAttest} from "../test/GuestEscrow.t.sol";

/// Anvil fork of Base mainnet only, after MainnetLaunch. Keys are anvil's dev keys; the owners are dev accounts standing in
/// for the Safes. `open` runs deposit, accept, register, claim and close; the caller then advances the fork past CLAIM_GRACE
/// and runs `settle` (withdraw). The claim path runs on a second GuestEscrow wired to MockGuestAttest (no real guest
/// assertion exists for mainnet yet); the deployed GuestEscrow takes deposit, accept, close and withdraw.
contract MainnetSmoke is Script {
    uint256 constant RELAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // anvil 0
    uint256 constant ESCROW_OWNER = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a; // anvil 2
    uint256 constant MINT_OWNER = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6; // anvil 3
    uint256 constant BUYER = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a; // anvil 4
    uint256 constant GUEST = uint256(keccak256("layover mainnet smoke guest key"));
    address constant OPERATOR = 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc; // anvil 5
    bytes32 constant IMAGE = keccak256("smoke image");
    bytes32 constant MANIFEST = keccak256("smoke manifest");
    bytes32 constant CDHASH = keccak256("smoke runner cdhash");
    bytes32 constant TERMS = keccak256("layover-terms/1 smoke");

    function open() external {
        require(block.chainid == 8453, "Base mainnet fork only");
        LayoverCredit layc = LayoverCredit(vm.envAddress("LAYC"));
        GuestEscrow real = GuestEscrow(vm.envAddress("GUEST_ESCROW"));
        address buyer = vm.addr(BUYER);
        bytes32 caller = sha256("agent");

        vm.broadcast(MINT_OWNER);
        layc.transfer(buyer, 5e6); // a starter grant
        vm.startBroadcast(RELAYER);
        address stubAt = vm.computeCreateAddress(vm.addr(RELAYER), vm.getNonce(vm.addr(RELAYER)) + 1);
        MockGuestAttest mock = new MockGuestAttest(stubAt);
        GuestEscrow stub = new GuestEscrow(address(layc), vm.addr(ESCROW_OWNER), IGuestAttest(address(mock)));
        vm.stopBroadcast();
        require(address(stub) == stubAt, "stub address");
        console2.log("stub GuestEscrow", address(stub));

        // Stub escrow: x402 deposit, signed accept, guest key, claim, signed close. The relayer sends every buyer action.
        vm.broadcast(ESCROW_OWNER);
        stub.setWorkload(IMAGE, MANIFEST, caller, true);
        vm.startBroadcast(RELAYER);
        _depositWithAuthorization(layc, stub, buyer, 2e6, bytes32(uint256(1)));
        stub.acceptTermsFor(buyer, TERMS, OPERATOR, 1e6, _sign(BUYER, stub.termsDigest(buyer, TERMS, OPERATOR, 1e6)));
        GuestEscrow.Attested memory a = GuestEscrow.Attested(IMAGE, MANIFEST, keccak256("run"), caller);
        GuestEscrow.Event[] memory ev = new GuestEscrow.Event[](1);
        ev[0] = GuestEscrow.Event("system-ready", "");
        bytes32 ctx = sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", a.image, a.manifest, a.run, stub.eventHead(ev), a.caller,
            abi.encode(vm.addr(GUEST), OPERATOR)));
        stub.registerGuestKey(vm.addr(GUEST), OPERATOR, a, ev, abi.encode(ctx, CDHASH));
        uint256 before = layc.balanceOf(OPERATOR);
        stub.claim(buyer, TERMS, 4e5, _sign(GUEST, stub.claimDigest(buyer, OPERATOR, TERMS, 4e5)));
        require(layc.balanceOf(OPERATOR) - before == 4e5, "claim paid");
        stub.closeTermsFor(buyer, TERMS, _sign(BUYER, stub.closeDigest(buyer, TERMS)));
        vm.stopBroadcast();

        // Deployed escrow: plain deposit, accept, close; withdraw what exposure leaves.
        vm.startBroadcast(BUYER);
        layc.approve(address(real), 1e6);
        real.deposit(1e6);
        real.acceptTerms(TERMS, OPERATOR, 5e5);
        real.closeTerms(TERMS);
        real.withdraw(5e5, new bytes32[](0));
        vm.stopBroadcast();
        require(real.exposure(buyer) == 5e5 && real.balance(buyer) == 5e5, "real escrow state");
        console2.log("open done: stub claimed 0.4 LAYC to the operator; real escrow withdrew 0.5 of 1 LAYC");
    }

    function settle() external {
        require(block.chainid == 8453, "Base mainnet fork only");
        LayoverCredit layc = LayoverCredit(vm.envAddress("LAYC"));
        GuestEscrow real = GuestEscrow(vm.envAddress("GUEST_ESCROW"));
        GuestEscrow stub = GuestEscrow(vm.envAddress("STUB_ESCROW"));
        address buyer = vm.addr(BUYER);
        bytes32[] memory expired = new bytes32[](1);
        expired[0] = TERMS;
        uint256 before = layc.balanceOf(buyer);
        vm.startBroadcast(RELAYER);
        stub.withdrawFor(buyer, buyer, 16e5, _sign(BUYER, stub.withdrawDigest(buyer, buyer, 16e5, stub.withdrawNonce(buyer))), expired);
        vm.stopBroadcast();
        vm.broadcast(BUYER);
        real.withdraw(5e5, expired);
        require(layc.balanceOf(buyer) - before == 21e5, "withdrawn");
        require(stub.balance(buyer) == 0 && real.balance(buyer) == 0 && stub.exposure(buyer) == 0 && real.exposure(buyer) == 0, "drained");
        console2.log("settle done: buyer withdrew 1.6 (stub) + 0.5 (real) LAYC after CLAIM_GRACE");
    }

    function _depositWithAuthorization(LayoverCredit layc, GuestEscrow esc, address from, uint256 value, bytes32 nonce) internal {
        bytes32 s = keccak256(abi.encode(layc.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), from, address(esc), value, 0, type(uint256).max, nonce));
        esc.depositWithAuthorization(from, value, 0, type(uint256).max, nonce,
            _sign(BUYER, keccak256(abi.encodePacked("\x19\x01", layc.DOMAIN_SEPARATOR(), s))));
    }
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
