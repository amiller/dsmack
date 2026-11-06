// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {GuestEscrow, IGuestAttest} from "../../src/GuestEscrow.sol";
import {LayoverCredit} from "../../src/LayoverCredit.sol";
import {MockGuestAttest} from "../GuestEscrow.t.sol";

/// Drives GuestEscrow through random sequences. The handler is the escrow and token owner. Transition properties
/// (claim oracle, payee, monotonic cumulativeOwed, withdraw bound) are checked inside each action and recorded in
/// `violation`, since a handler assertion would only revert and be discarded under fail_on_revert = false.
contract GuestEscrowHandler is Test {
    GuestEscrow public esc;
    LayoverCredit public token;
    MockGuestAttest public attest;
    uint256[3] buyerPk = [uint256(0xB01), 0xB02, 0xB03];
    uint256[3] guestPk = [uint256(0x6E01), 0x6E02, 0x6E03];
    address[2] public operators = [address(0x0901), address(0x0902)];
    address[2] public recipients = [address(0x7001), address(0x7002)];
    address public sponsor = address(0x5905);
    bytes32[3] public hashes = [keccak256("t0"), keccak256("t1"), keccak256("t2")];
    bytes32[2] images = [keccak256("img0"), keccak256("img1")];
    bytes32 constant MANIFEST = keccak256("manifest");
    bytes32 constant CALLER = keccak256("caller");
    address[] public holders;
    mapping(address => uint256) public expected;
    mapping(bytes32 => uint256) lastClaimed;
    uint256 public authNonce;
    string public violation;
    mapping(string => uint256) public calls;

    constructor() {
        vm.warp(30 weeks);
        token = new LayoverCredit(address(this), 1_000_000e6);
        attest = new MockGuestAttest(vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1));
        esc = new GuestEscrow(address(token), address(this), attest);
        for (uint256 i; i < 2; i++) esc.setWorkload(images[i], MANIFEST, CALLER, true);
        holders.push(address(esc)); holders.push(sponsor);
        for (uint256 i; i < 3; i++) { address b = buyer(i); holders.push(b); _give(b, 10_000e6); vm.prank(b); token.approve(address(esc), type(uint256).max); }
        for (uint256 i; i < 2; i++) { holders.push(operators[i]); holders.push(recipients[i]); }
        _give(sponsor, 10_000e6);
        vm.prank(sponsor); token.approve(address(esc), type(uint256).max);
    }
    function _give(address to, uint256 a) internal { token.transfer(to, a); expected[to] += a; }
    function buyer(uint256 i) public view returns (address) { return vm.addr(buyerPk[i % 3]); }
    function guest(uint256 i) public view returns (address) { return vm.addr(guestPk[i % 3]); }
    function holderCount() external view returns (uint256) { return holders.length; }
    function _flag(string memory why) internal { if (bytes(violation).length == 0) violation = why; }
    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) { (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d); return abi.encodePacked(r, s, v); }

    function _move(address from, address to, uint256 a) internal { expected[from] -= a; expected[to] += a; }

    function deposit(uint256 b, uint256 amount) external {
        address u = buyer(b); amount = bound(amount, 1, 2_000e6);
        vm.prank(u); esc.deposit(amount);
        _move(u, address(esc), amount); calls["deposit"]++;
    }
    function depositFor(uint256 b, uint256 amount) external {
        address u = buyer(b); amount = bound(amount, 1, 2_000e6);
        vm.prank(sponsor); esc.depositFor(u, amount);
        _move(sponsor, address(esc), amount); calls["depositFor"]++;
    }
    function depositWithAuthorization(uint256 b, uint256 amount) external {
        address u = buyer(b); amount = bound(amount, 1, 2_000e6);
        bytes32 nonce = keccak256(abi.encode(authNonce++));
        bytes32 h = keccak256(abi.encode(token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), u, address(esc), amount, 0, block.timestamp + 1 hours, nonce));
        bytes memory sig = _sign(buyerPk[b % 3], keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), h)));
        esc.depositWithAuthorization(u, amount, 0, block.timestamp + 1 hours, nonce, sig);
        _move(u, address(esc), amount); calls["depositWithAuthorization"]++;
        vm.expectRevert("authorization used");
        esc.depositWithAuthorization(u, amount, 0, block.timestamp + 1 hours, nonce, sig);
    }
    function acceptTerms(uint256 b, uint256 h, uint256 op, uint256 cap, bool relayed) external {
        address u = buyer(b); bytes32 th = hashes[h % 3]; address o = operators[op % 2]; cap = bound(cap, 1, 3_000e6);
        if (esc.exposure(u) + cap > esc.balance(u) && cap % 4 != 0) return; // keep most terms collateralized, a quarter not
        if (relayed) esc.acceptTermsFor(u, th, o, cap, _sign(buyerPk[b % 3], esc.termsDigest(u, th, o, cap)));
        else { vm.prank(u); esc.acceptTerms(th, o, cap); }
        calls["acceptTerms"]++;
    }
    function closeTerms(uint256 b, uint256 h, bool relayed) external {
        address u = buyer(b); bytes32 th = hashes[h % 3];
        (address o,, uint64 closedAt,) = esc.terms(u, th);
        if (o == address(0) || closedAt != 0) return;
        if (relayed) esc.closeTermsFor(u, th, _sign(buyerPk[b % 3], esc.closeDigest(u, th)));
        else { vm.prank(u); esc.closeTerms(th); }
        calls["closeTerms"]++;
    }
    function registerGuestKey(uint256 k, uint256 op, uint256 w) external {
        address key = guest(k); address o = operators[op % 2]; bytes32 img = images[w % 2];
        bool predicted = !_registered(key) && esc.approved(esc.workloadId(img, MANIFEST, CALLER));
        (bool success,) = address(esc).call(_registration(key, o, img));
        if (success != predicted) _flag("registerGuestKey oracle");
        if (success) calls["registerGuestKey"]++;
    }
    /// The MockGuestAttest proof is abi.encode(context, cdhash): the verifier stub accepts any assertion over the right context.
    function _registration(address key, address o, bytes32 img) internal view returns (bytes memory) {
        GuestEscrow.Attested memory a = GuestEscrow.Attested(img, MANIFEST, keccak256("run"), CALLER);
        GuestEscrow.Event[] memory ev = new GuestEscrow.Event[](1); ev[0] = GuestEscrow.Event("system-ready", "");
        bytes32 ctx = sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", a.image, a.manifest, a.run, esc.eventHead(ev), a.caller, abi.encode(key, o)));
        return abi.encodeCall(esc.registerGuestKey, (key, o, a, ev, abi.encode(ctx, keccak256("cdhash"))));
    }
    function _registered(address key) internal view returns (bool) { (address o,,,) = esc.guestKeys(key); return o != address(0); }
    function setWorkload(uint256 w, bool ok) external {
        esc.setWorkload(images[w % 2], MANIFEST, CALLER, ok); calls["setWorkload"]++;
    }

    struct C { address u; bytes32 th; address key; address op; uint256 cap; uint64 closedAt; uint256 prev; uint256 cum; uint256 total; bool predicted; }
    function claim(uint256 b, uint256 h, uint256 k, uint256 inc) external {
        C memory c; c.u = buyer(b); c.th = hashes[h % 3]; c.key = guest(k);
        (c.op, c.cap, c.closedAt,) = esc.terms(c.u, c.th);
        if (c.op == address(0)) return;
        c.prev = esc.claimed(c.u, c.th, c.key); c.total = esc.totalClaimed(c.u, c.th);
        uint256 room = c.cap - c.total; if (esc.balance(c.u) < room) room = esc.balance(c.u);
        c.cum = c.prev + (room > 0 && inc % 8 != 0 ? bound(inc, 1, room) : bound(inc, 0, c.cap + 1));
        (address kop, bytes32 w,,) = esc.guestKeys(c.key);
        c.predicted = (c.closedAt == 0 || block.timestamp < uint256(c.closedAt) + esc.CLAIM_GRACE()) && c.cum <= c.cap
            && kop == c.op && esc.approved(w) && c.cum > c.prev && c.total + (c.cum - c.prev) <= c.cap && c.cum - c.prev <= esc.balance(c.u);
        (bool success,) = address(esc).call(abi.encodeCall(esc.claim, (c.u, c.th, c.cum, _sign(guestPk[k % 3], esc.claimDigest(c.u, c.op, c.th, c.cum)))));
        if (success != c.predicted) _flag("claim oracle");
        if (success && kop != address(0) && !esc.approved(w)) _flag("removed workload claimed");
        if (!success) return;
        _move(address(esc), c.op, c.cum - c.prev);
        _checkBalances();
        calls["claim"]++;
    }
    struct W { address u; address to; uint256 amount; uint256 bal; uint256 exp; bytes32[] expired; bool success; }
    function withdraw(uint256 b, uint256 amount, uint256 releaseMask, bool relayed, uint256 r, bool exact) external {
        W memory w; w.u = buyer(b); w.expired = _expired(w.u, releaseMask);
        w.bal = esc.balance(w.u); w.exp = esc.exposure(w.u) - _rest(w.u, w.expired);
        w.amount = exact && w.bal > w.exp ? w.bal - w.exp : bound(amount, 1, w.bal + 1);
        w.to = relayed ? recipients[r % 2] : w.u;
        if (relayed) w.success = _withdrawFor(buyerPk[b % 3], w);
        else { vm.prank(w.u); (w.success,) = address(esc).call(abi.encodeCall(esc.withdraw, (w.amount, w.expired))); }
        if (w.success != (w.amount + w.exp <= w.bal)) _flag("withdraw oracle");
        if (!w.success) return;
        if (w.amount + esc.exposure(w.u) > w.bal) _flag("withdraw above balance - exposure");
        _move(address(esc), w.to, w.amount);
        _checkBalances();
        calls["withdraw"]++;
    }
    function _rest(address u, bytes32[] memory expired) internal view returns (uint256 rest) {
        for (uint256 i; i < expired.length; i++) { (, uint256 cap,,) = esc.terms(u, expired[i]); rest += cap - esc.totalClaimed(u, expired[i]); }
    }
    function _withdrawFor(uint256 pk, W memory w) internal returns (bool success) {
        bytes memory sig = _sign(pk, esc.withdrawDigest(w.u, w.to, w.amount, esc.withdrawNonce(w.u)));
        (success,) = address(esc).call(abi.encodeCall(esc.withdrawFor, (w.u, w.to, w.amount, sig, w.expired)));
        if (!success) return false;
        (bool again,) = address(esc).call(abi.encodeCall(esc.withdrawFor, (w.u, w.to, w.amount, sig, new bytes32[](0))));
        if (again) _flag("withdrawFor replay");
    }
    function _expired(address u, uint256 mask) internal view returns (bytes32[] memory out) {
        out = new bytes32[](3); uint256 n;
        for (uint256 i; i < 3; i++) {
            (address o,, uint64 closedAt, bool released) = esc.terms(u, hashes[i]);
            if (o != address(0) && closedAt != 0 && !released && block.timestamp >= uint256(closedAt) + esc.CLAIM_GRACE() && (mask >> i) & 1 == 1) out[n++] = hashes[i];
        }
        assembly ("memory-safe") { mstore(out, n) }
    }
    function warp(uint256 dt) external { vm.warp(block.timestamp + bound(dt, 1, 3 days)); calls["warp"]++; }

    /// Every holder's token balance matches the ghost ledger after each money-moving action, so the action paid exactly
    /// the address the handler predicted (operator for a claim, `to` for a withdraw) and nobody else.
    function _checkBalances() internal {
        for (uint256 i; i < holders.length; i++) if (token.balanceOf(holders[i]) != expected[holders[i]]) _flag("unexpected payee");
    }
    /// Monotonic per-key cumulativeOwed, checked across every action by the invariant below.
    function checkMonotonic() external {
        for (uint256 b; b < 3; b++) for (uint256 h; h < 3; h++) for (uint256 k; k < 3; k++) {
            bytes32 slot = keccak256(abi.encode(b, h, k));
            uint256 now_ = esc.claimed(buyer(b), hashes[h], guest(k));
            if (now_ < lastClaimed[slot]) _flag("cumulativeOwed decreased");
            lastClaimed[slot] = now_;
        }
    }
}

contract GuestEscrowInvariantTest is Test {
    GuestEscrowHandler h;
    GuestEscrow esc;
    LayoverCredit token;

    function setUp() public {
        h = new GuestEscrowHandler();
        esc = h.esc(); token = h.token();
        targetContract(address(h));
        bytes4[] memory s = new bytes4[](10);
        (s[0], s[1], s[2], s[3], s[4]) = (h.deposit.selector, h.depositFor.selector, h.depositWithAuthorization.selector, h.acceptTerms.selector, h.closeTerms.selector);
        (s[5], s[6], s[7], s[8], s[9]) = (h.registerGuestKey.selector, h.setWorkload.selector, h.claim.selector, h.withdraw.selector, h.warp.selector);
        targetSelector(FuzzSelector(address(h), s));
    }

    function invariant_noTransitionViolation() public {
        h.checkMonotonic();
        assertEq(h.violation(), "");
    }
    /// token.balanceOf(escrow) == Σ balance(buyer)
    function invariant_tokenBalanceEqualsSumOfBalances() public view {
        uint256 sum;
        for (uint256 i; i < 3; i++) sum += esc.balance(h.buyer(i));
        assertEq(token.balanceOf(address(esc)), sum);
    }
    /// totalClaimed ≤ cap, and totalClaimed == Σ over guest keys of claimed.
    function invariant_paidWithinCap() public view {
        for (uint256 b; b < 3; b++) for (uint256 i; i < 3; i++) {
            address u = h.buyer(b); bytes32 th = h.hashes(i);
            (, uint256 cap,,) = esc.terms(u, th);
            uint256 tot = esc.totalClaimed(u, th);
            assertLe(tot, cap);
            assertEq(tot, esc.claimed(u, th, h.guest(0)) + esc.claimed(u, th, h.guest(1)) + esc.claimed(u, th, h.guest(2)));
        }
    }
    /// exposure == Σ over accepted, unreleased terms of (cap − totalClaimed). Release is lazy: closed terms past
    /// CLAIM_GRACE stay in exposure until a withdraw names them in `expired`.
    function invariant_exposureAccounting() public view {
        for (uint256 b; b < 3; b++) {
            address u = h.buyer(b); uint256 sum;
            for (uint256 i; i < 3; i++) {
                (address o, uint256 cap,, bool released) = esc.terms(u, h.hashes(i));
                if (o != address(0) && !released) sum += cap - esc.totalClaimed(u, h.hashes(i));
            }
            assertEq(esc.exposure(u), sum);
        }
    }
    /// withdrawable ≤ balance − exposure, and paid + withdrawn ≤ deposits.
    function invariant_withdrawableBound() public view {
        for (uint256 b; b < 3; b++) {
            address u = h.buyer(b);
            uint256 bal = esc.balance(u); uint256 e = esc.exposure(u);
            assertEq(esc.withdrawable(u), bal > e ? bal - e : 0);
            assertLe(esc.paid(u) + esc.withdrawn(u), esc.deposits(u));
        }
    }
    /// Every accepted term is funded: exposure <= balance. Fails on escrow-terms (finding 2): _accept does not check it.
    function invariant_exposureFunded() public view {
        for (uint256 b; b < 3; b++) assertLe(esc.exposure(h.buyer(b)), esc.balance(h.buyer(b)));
    }
    /// The only token flows are the ones the ghost ledger predicted (deposits in, claims to operators, withdrawals to `to`).
    function invariant_ledgerMatchesTokenBalances() public view {
        for (uint256 i; i < h.holderCount(); i++) { address a = h.holders(i); assertEq(token.balanceOf(a), h.expected(a)); }
    }
    function afterInvariant() public view {
        string[10] memory n = ["deposit", "depositFor", "depositWithAuthorization", "acceptTerms", "closeTerms", "registerGuestKey", "setWorkload", "claim", "withdraw", "warp"];
        for (uint256 i; i < 10; i++) console.log(n[i], h.calls(n[i]));
    }
}
