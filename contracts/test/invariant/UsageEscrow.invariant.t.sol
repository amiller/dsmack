// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {UsageEscrow} from "../../src/UsageEscrow.sol";
import {LayoverCredit} from "../../src/LayoverCredit.sol";

/// Drives UsageEscrow with LAYC as the token. The handler is the owner and registers broker 0 at deploy; it rotates
/// between two broker keys, and a third key that is never the broker signs some claims.
contract UsageEscrowHandler is Test {
    UsageEscrow public esc;
    LayoverCredit public token;
    uint256[3] userPk = [uint256(0xC01), 0xC02, 0xC03];
    uint256[3] brokerPk = [uint256(0xBB01), 0xBB02, 0xBBFF];
    address[2] public operators = [address(0x0901), address(0x0902)];
    address public sponsor = address(0x5905);
    address public stranger = address(0x5757);
    bytes32[3] public hashes = [keccak256("t0"), keccak256("t1"), keccak256("t2")];
    address public broker;
    uint256 authNonce;
    string public violation;
    mapping(string => uint256) public calls;

    constructor() {
        vm.warp(30 weeks);
        token = new LayoverCredit(address(this), 1_000_000e6);
        esc = new UsageEscrow(address(token), address(this));
        broker = vm.addr(brokerPk[0]);
        esc.registerBroker(broker);
        for (uint256 i; i < 3; i++) { token.transfer(user(i), 10_000e6); vm.prank(user(i)); token.approve(address(esc), type(uint256).max); }
        token.transfer(sponsor, 10_000e6);
        vm.prank(sponsor); token.approve(address(esc), type(uint256).max);
    }
    function user(uint256 i) public view returns (address) { return vm.addr(userPk[i % 3]); }
    function _flag(string memory why) internal { if (bytes(violation).length == 0) violation = why; }
    function _sign(uint256 pk, bytes32 d) internal pure returns (bytes memory) { (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d); return abi.encodePacked(r, s, v); }

    function deposit(uint256 u, uint256 amount, bool sponsored) external {
        amount = bound(amount, 1, 2_000e6);
        vm.prank(sponsored ? sponsor : user(u));
        (bool ok,) = address(esc).call(sponsored ? abi.encodeCall(esc.depositFor, (user(u), amount)) : abi.encodeCall(esc.deposit, (amount)));
        if (ok == (esc.exitRequestedAt(user(u)) != 0)) _flag("deposit oracle");
        if (ok) calls["deposit"]++;
    }
    function depositWithAuthorization(uint256 u, uint256 amount) external {
        address a = user(u); amount = bound(amount, 1, 2_000e6);
        if (esc.exitRequestedAt(a) != 0) return;
        bytes32 nonce = keccak256(abi.encode(authNonce++));
        bytes32 h = keccak256(abi.encode(token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), a, address(esc), amount, 0, block.timestamp + 1 hours, nonce));
        esc.depositWithAuthorization(a, amount, 0, block.timestamp + 1 hours, nonce, _sign(userPk[u % 3], keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), h))));
        calls["depositWithAuthorization"]++;
    }
    function acceptTerms(uint256 u, uint256 h, uint256 op, uint256 cap, bool relayed) external {
        address a = user(u); bytes32 th = hashes[h % 3]; address o = operators[op % 2]; cap = bound(cap, 1, 3_000e6);
        if (relayed) esc.acceptTermsFor(a, th, o, cap, _sign(userPk[u % 3], esc.termsDigest(a, th, o, cap)));
        else { vm.prank(a); esc.acceptTerms(th, o, cap); }
        calls["acceptTerms"]++;
    }

    struct C { address u; bytes32 th; address op; uint256 cap; uint256 prev; UsageEscrow.Claim c; uint256 signer; bool predicted; }
    function claim(uint256 u, uint256 h, uint256 inc, uint256 period, uint256 signer) external {
        C memory x; x.u = user(u); x.th = hashes[h % 3];
        (x.op, x.cap) = esc.terms(x.u, x.th);
        if (x.op == address(0)) return;
        x.prev = esc.claimed(x.u, x.th);
        uint256 room = x.cap - x.prev; if (esc.balance(x.u) < room) room = esc.balance(x.u);
        uint64 now_ = uint64(block.timestamp / 1 weeks); uint64 last = esc.claimPeriod(x.u, x.th);
        x.c = UsageEscrow.Claim(x.op, x.th, x.prev + (room > 0 && inc % 8 != 0 ? bound(inc, 1, room) : bound(inc, 0, x.cap + 1)),
            period % 6 == 0 ? uint64(bound(period, 0, now_ + 1)) : uint64(bound(period, last, now_)));
        x.signer = signer % 5 == 0 ? brokerPk[2] : (vm.addr(brokerPk[0]) == broker ? brokerPk[0] : brokerPk[1]);
        uint64 exit = esc.exitRequestedAt(x.u);
        x.predicted = x.c.cumulativeOwed <= x.cap && vm.addr(x.signer) == broker && x.c.period <= now_ && x.c.period >= last
            && (exit == 0 || block.timestamp < uint256(exit) + esc.ESCAPE_DELAY()) && x.c.cumulativeOwed > x.prev && x.c.cumulativeOwed - x.prev <= esc.balance(x.u);
        uint256 opBefore = token.balanceOf(x.op);
        (bool ok,) = address(esc).call(abi.encodeCall(esc.claim, (x.u, x.c, _sign(x.signer, esc.claimDigest(x.u, x.c)))));
        if (ok != x.predicted) _flag("claim oracle");
        if (ok && x.c.period > now_) _flag("claim for a future period");
        if (ok && token.balanceOf(x.op) != opBefore + x.c.cumulativeOwed - x.prev) _flag("claim payee");
        if (ok) calls["claim"]++;
    }
    function requestExit(uint256 u) external {
        vm.prank(user(u)); esc.requestExit();
        calls["requestExit"]++;
    }
    function withdraw(uint256 u) external {
        address a = user(u); uint64 exit = esc.exitRequestedAt(a); uint256 bal = esc.balance(a);
        uint256 before = token.balanceOf(a);
        vm.prank(a);
        (bool ok,) = address(esc).call(abi.encodeCall(esc.withdraw, ()));
        if (ok != (exit != 0 && block.timestamp >= uint256(exit) + esc.ESCAPE_DELAY() && bal > 0)) _flag("withdraw oracle");
        if (ok && token.balanceOf(a) != before + bal) _flag("withdraw amount");
        if (ok) calls["withdraw"]++;
    }
    function rotateBroker(bool toFirst) external {
        address next = vm.addr(brokerPk[toFirst ? 0 : 1]);
        (bool ok,) = address(esc).call(abi.encodeCall(esc.rotateBroker, (next)));
        if (ok != (next != broker)) _flag("rotate oracle");
        if (ok) { broker = next; calls["rotateBroker"]++; }
    }
    function strangerSetsBroker(bool rotate) external {
        vm.prank(stranger);
        (bool ok,) = address(esc).call(rotate ? abi.encodeCall(esc.rotateBroker, (stranger)) : abi.encodeCall(esc.registerBroker, (stranger)));
        if (ok) _flag("stranger set broker");
        (ok,) = address(esc).call(abi.encodeCall(esc.registerBroker, (stranger)));
        if (ok) _flag("registerBroker twice");
    }
    function warp(uint256 dt) external { vm.warp(block.timestamp + bound(dt, 1, 5 days)); calls["warp"]++; }
}

contract UsageEscrowInvariantTest is Test {
    UsageEscrowHandler h;
    UsageEscrow esc;
    LayoverCredit token;

    function setUp() public {
        h = new UsageEscrowHandler();
        esc = h.esc(); token = h.token();
        targetContract(address(h));
    }
    function invariant_noTransitionViolation() public view { assertEq(h.violation(), ""); }
    function invariant_paidWithinDeposits() public view {
        for (uint256 i; i < 3; i++) {
            address u = h.user(i);
            assertLe(esc.paid(u), esc.deposits(u));
            assertLe(esc.paid(u) + esc.withdrawn(u), esc.deposits(u));
        }
    }
    function invariant_claimedWithinCap() public view {
        for (uint256 i; i < 3; i++) for (uint256 j; j < 3; j++) {
            (, uint256 cap) = esc.terms(h.user(i), h.hashes(j));
            assertLe(esc.claimed(h.user(i), h.hashes(j)), cap);
        }
    }
    function invariant_tokenBalanceEqualsSumOfBalances() public view {
        uint256 sum;
        for (uint256 i; i < 3; i++) sum += esc.balance(h.user(i));
        assertEq(token.balanceOf(address(esc)), sum);
    }
    function invariant_brokerOnlyByOwner() public view { assertEq(esc.brokerSigner(), h.broker()); }
    function afterInvariant() public view {
        string[8] memory n = ["deposit", "depositWithAuthorization", "acceptTerms", "claim", "requestExit", "withdraw", "rotateBroker", "warp"];
        for (uint256 i; i < 8; i++) console.log(n[i], h.calls(n[i]));
    }
}
