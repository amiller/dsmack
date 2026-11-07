// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {LayoverCredit} from "../../src/LayoverCredit.sol";

/// LAYC mints nothing at deploy; the handler is the owner and mints the actors' starting balances. Epochs are a day apart,
/// and advanceEpoch runs up to 400 of them per call so random sequences reach CAP. `stranger` actions must revert.
contract LayoverCreditHandler is Test {
    LayoverCredit public c;
    uint256 public constant GENESIS = 0;
    uint256[3] pk = [uint256(0xA1), 0xA2, 0xA3];
    address public stranger = address(0x5757);
    uint256 public minted;
    uint256 public scheduled;
    uint256 nonceSeq;
    bytes32[] usedNonces;
    address[] usedBy;
    string public violation;
    mapping(string => uint256) public calls;

    constructor() {
        vm.warp(1000);
        c = new LayoverCredit(address(this));
        scheduled = c.reward(0);
        for (uint256 i; i < 3; i++) c.mint(actor(i), 1_000e6);
        minted = 3_000e6;
    }
    function actor(uint256 i) public view returns (address) { return vm.addr(pk[i % 3]); }
    function _flag(string memory why) internal { if (bytes(violation).length == 0) violation = why; }

    function mint(uint256 to, uint256 amount) external {
        uint256 room = c.reward(c.epoch()) - c.mintedInEpoch();
        amount = room > 0 && amount % 5 != 0 ? bound(amount, 1, room) : bound(amount, 1, c.INITIAL_REWARD() + 1);
        bool predicted = c.mintedInEpoch() + amount <= c.reward(c.epoch()) && c.totalSupply() + amount <= c.CAP();
        (bool ok,) = address(c).call(abi.encodeCall(c.mint, (actor(to), amount)));
        if (ok != predicted) _flag("mint oracle");
        if (ok) { minted += amount; calls["mint"]++; }
    }
    function advanceEpoch(uint256 n) external {
        n = bound(n, 1, 400);
        for (uint256 i; i < n; i++) {
            uint256 before = c.reward(c.epoch());
            vm.warp(block.timestamp + 1 days);
            c.advanceEpoch();
            uint256 e = c.epoch();
            if (c.mintedInEpoch() != 0) _flag("mintedInEpoch not reset");
            if (e % c.HALVING_EPOCHS() == 0 ? c.reward(e) != before >> 1 : c.reward(e) != before) _flag("halving schedule");
            scheduled += c.reward(e);
        }
        calls["advanceEpoch"]++;
    }
    function strangerMint(uint256 amount) external {
        vm.prank(stranger);
        (bool ok,) = address(c).call(abi.encodeCall(c.mint, (stranger, bound(amount, 1, 10))));
        if (ok) _flag("stranger minted");
    }
    function strangerAdvance() external {
        vm.prank(stranger);
        (bool ok,) = address(c).call(abi.encodeCall(c.advanceEpoch, ()));
        if (ok) _flag("stranger advanced");
    }
    function transfer(uint256 from, uint256 to, uint256 amount) external {
        amount = bound(amount, 0, c.balanceOf(actor(from)));
        vm.prank(actor(from)); c.transfer(actor(to), amount);
        calls["transfer"]++;
    }
    function _auth(uint256 from, bytes32 typehash, address to, uint256 value, bytes32 nonce) internal view returns (uint8, bytes32, bytes32) {
        bytes32 h = keccak256(abi.encode(typehash, actor(from), to, value, 0, block.timestamp + 1 hours, nonce));
        return vm.sign(pk[from % 3], keccak256(abi.encodePacked("\x19\x01", c.DOMAIN_SEPARATOR(), h)));
    }
    function transferWithAuthorization(uint256 from, uint256 to, uint256 amount, bool receive_) external {
        address f = actor(from); address t = actor(to);
        amount = bound(amount, 0, c.balanceOf(f));
        bytes32 nonce = keccak256(abi.encode(nonceSeq++));
        (uint8 v, bytes32 r, bytes32 s) = _auth(from, receive_ ? c.RECEIVE_WITH_AUTHORIZATION_TYPEHASH() : c.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), t, amount, nonce);
        if (receive_) { vm.prank(t); c.receiveWithAuthorization(f, t, amount, 0, block.timestamp + 1 hours, nonce, v, r, s); }
        else c.transferWithAuthorization(f, t, amount, 0, block.timestamp + 1 hours, nonce, v, r, s);
        usedNonces.push(nonce); usedBy.push(f);
        calls["transferWithAuthorization"]++;
    }
    function cancelAuthorization(uint256 from) external {
        bytes32 nonce = keccak256(abi.encode(nonceSeq++));
        bytes32 h = keccak256(abi.encode(c.CANCEL_AUTHORIZATION_TYPEHASH(), actor(from), nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk[from % 3], keccak256(abi.encodePacked("\x19\x01", c.DOMAIN_SEPARATOR(), h)));
        c.cancelAuthorization(actor(from), nonce, v, r, s);
        usedNonces.push(nonce); usedBy.push(actor(from));
        calls["cancelAuthorization"]++;
    }
    /// Re-signs a used (or cancelled) nonce with fresh parameters; every one must be refused.
    function replayAuthorization(uint256 i, uint256 to, bool receive_) external {
        if (usedNonces.length == 0) return;
        i = i % usedNonces.length;
        address f = usedBy[i]; uint256 from = f == actor(0) ? 0 : f == actor(1) ? 1 : 2;
        (uint8 v, bytes32 r, bytes32 s) = _auth(from, receive_ ? c.RECEIVE_WITH_AUTHORIZATION_TYPEHASH() : c.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), actor(to), 0, usedNonces[i]);
        vm.prank(actor(to));
        (bool ok,) = address(c).call(receive_
            ? abi.encodeCall(c.receiveWithAuthorization, (f, actor(to), 0, 0, block.timestamp + 1 hours, usedNonces[i], v, r, s))
            : abi.encodeCall(c.transferWithAuthorization, (f, actor(to), 0, 0, block.timestamp + 1 hours, usedNonces[i], v, r, s)));
        if (ok) _flag("authorization replayed");
        calls["replayAuthorization"]++;
    }
    function warp(uint256 dt) external { vm.warp(block.timestamp + bound(dt, 1, 1 days)); }
}

contract LayoverCreditInvariantTest is Test {
    LayoverCreditHandler h;
    LayoverCredit c;

    function setUp() public {
        h = new LayoverCreditHandler();
        c = h.c();
        targetContract(address(h));
    }
    function invariant_noTransitionViolation() public view { assertEq(h.violation(), ""); }
    function invariant_supplyCapped() public view { assertLe(c.totalSupply(), c.CAP()); }
    function invariant_mintedInEpochWithinReward() public view { assertLe(c.mintedInEpoch(), c.reward(c.epoch())); }
    /// Supply is genesis plus owner mints, and never more than genesis plus every epoch's reward so far.
    function invariant_supplyFollowsSchedule() public view {
        assertEq(c.totalSupply(), h.GENESIS() + h.minted());
        assertLe(c.totalSupply(), h.GENESIS() + h.scheduled());
    }
    function invariant_balancesSumToSupply() public view {
        uint256 sum = c.balanceOf(address(h)) + c.balanceOf(h.stranger());
        for (uint256 i; i < 3; i++) sum += c.balanceOf(h.actor(i));
        assertEq(sum, c.totalSupply());
    }
    function afterInvariant() public view {
        console.log("epoch", c.epoch(), "supply", c.totalSupply());
        string[5] memory n = ["mint", "advanceEpoch", "transfer", "transferWithAuthorization", "replayAuthorization"];
        for (uint256 i; i < 5; i++) console.log(n[i], h.calls(n[i]));
    }
}

contract LayoverCreditHalvingTest is Test {
    LayoverCredit c = new LayoverCredit(address(1));
    /// reward halves exactly at each multiple of 1,461 and is constant in between.
    function testFuzz_rewardHalvesEvery1461(uint256 e) public view {
        e = bound(e, 0, 1461 * 300);
        assertEq(c.reward(e + 1461), c.reward(e) >> 1);
        assertEq(c.reward(e), c.reward(e - e % 1461));
        assertEq(c.reward(e), c.INITIAL_REWARD() >> (e / 1461));
    }
}
