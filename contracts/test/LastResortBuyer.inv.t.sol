// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {LastResortBuyer, LayoverCredit} from "../src/LastResortBuyer.sol";
import {Deploy, Minions, LastResortBuyerV2} from "./LastResortBuyer.t.sol";

/// Random sequences of advances, books, claims signed by registered minions, revoked minions, minions of a removed app
/// and strangers, and controller actions (revoke, remove and re-approve the app, mint attempts, upgrades, renounce).
contract Handler is Minions {
    LastResortBuyer public lrb;
    LayoverCredit public layc;
    address public controller = address(0xC0);
    uint256[3] keys = [uint256(0x3141), 0x2718, 0xBAD]; // two registered minions, one stranger
    uint256 public sumPayouts;
    uint256 public paidClaims;
    uint256 public maxEpoch;
    mapping(uint256 => uint256) public mintedIn;
    mapping(uint256 => mapping(address => uint256)) public mintedTo;
    mapping(bytes32 => uint256) public timesPaid;
    bool public foreignSignatureMinted;
    bool public controllerMinted;
    bool public claimOracleBroken; // a claim the rules say pays did not, or one they say fails did
    bytes32[] public ids;

    constructor() {
        vm.warp(1000);
        (lrb, layc) = Deploy.issuance(vm, controller, vm.addr(KMS_PK));
        vm.prank(controller); lrb.approveApp(APP);
        register(lrb, keys[0]);
        register(lrb, keys[1]);
    }
    function op(uint256 s) public pure returns (address) { return address(uint160(0x100 + s % 6)); }
    function signer() internal view returns (uint256) {
        for (uint256 i; i < 2; i++) if (lrb.isMinion(vm.addr(keys[i]))) return keys[i];
        return 0;
    }

    function advance(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 3 days));
        if (dt % 2 == 0 && layc.epochStart() + 1 days > block.timestamp) vm.warp(layc.epochStart() + 1 days); // on the boundary, so books fit their window
        try lrb.advance() { maxEpoch = layc.epoch(); } catch {}
    }
    function commitBook(uint256 n, uint256 k) external {
        uint256 e = layc.epoch();
        n = bound(n, 0, 40);
        uint256 key = keys[k % 3];
        bool valid = lrb.isMinion(vm.addr(key));
        try lrb.commitBook(e, n, bookSig(key, lrb, e, n)) {
            require(valid, "book from a non-minion accepted");
        } catch {}
    }
    function claim(uint256 idSeed, uint256 opSeed, uint256 k, bool stale) external {
        bytes32 id = bytes32(bound(idSeed, 1, 60));
        (address o, uint256 e) = (op(opSeed), stale && layc.epoch() > 0 ? layc.epoch() - 1 : layc.epoch());
        uint256 s = signer();
        if (lrb.units(layc.epoch()) == 0 && block.timestamp > layc.epochStart() + lrb.BOOK_WINDOW()) {
            // The window for this epoch's book has passed with no book: go to the next epoch's start.
            if (layc.epochStart() + 1 days > block.timestamp) vm.warp(layc.epochStart() + 1 days);
            lrb.advance();
            maxEpoch = layc.epoch();
        }
        if (s != 0 && lrb.units(layc.epoch()) == 0)
            lrb.commitBook(layc.epoch(), 8, bookSig(s, lrb, layc.epoch(), 8));
        uint256 key = keys[k % 3];
        bool valid = lrb.isMinion(vm.addr(key));
        uint256 cur = layc.epoch();
        bool pays = valid && e == cur && !lrb.paid(id) && lrb.units(cur) > 0 && lrb.paidUnits(cur) < lrb.units(cur)
            && lrb.paidTo(cur, o) + lrb.floor(cur) <= layc.reward(cur) / 4;
        uint256 before = layc.totalSupply();
        try lrb.claim(id, o, e, keccak256(abi.encode(id)), unitSig(key, lrb, id, o, e, keccak256(abi.encode(id)))) {
            if (!pays) claimOracleBroken = true;
            uint256 amount = layc.totalSupply() - before;
            if (!valid) foreignSignatureMinted = true;
            (sumPayouts, mintedIn[e], mintedTo[e][o]) = (sumPayouts + amount, mintedIn[e] + amount, mintedTo[e][o] + amount);
            if (timesPaid[id]++ == 0) ids.push(id);
            paidClaims++;
        } catch { if (pays) claimOracleBroken = true; }
    }
    function controllerActs(uint256 what) external {
        vm.startPrank(controller);
        uint256 w = what % 8;
        if (w == 0) lrb.revokeMinion(vm.addr(keys[1])); // keys[0] is only ever stopped by removeApp, so runs keep paying
        if (w == 1) lrb.removeApp(APP);
        if (w == 2 || w == 3) lrb.approveApp(APP);
        if (w == 4) try layc.mint(controller, 1) { controllerMinted = true; } catch {}
        if (w == 5) try layc.advanceEpoch() { controllerMinted = true; } catch {}
        if (w == 6) try lrb.upgradeTo(address(new LastResortBuyerV2(layc, vm.addr(KMS_PK)))) {} catch {}
        if (w == 7 && what % 64 == 7) lrb.renounceUpgrades();
        vm.stopPrank();
    }
    function idCount() external view returns (uint256) { return ids.length; }
}

/// forge-config: default.invariant.runs = 128
/// forge-config: default.invariant.depth = 128
contract LastResortBuyerInvariants is Test {
    Handler h;
    LastResortBuyer lrb;
    LayoverCredit layc;

    function setUp() public {
        h = new Handler();
        (lrb, layc) = (h.lrb(), h.layc());
        targetContract(address(h));
        bytes4[] memory actions = new bytes4[](4);
        (actions[0], actions[1], actions[2], actions[3]) = (h.advance.selector, h.commitBook.selector, h.claim.selector, h.controllerActs.selector);
        targetSelector(FuzzSelector(address(h), actions));
    }
    function invariant_supplyWithinCap() public view { assertLe(layc.totalSupply(), layc.CAP()); }
    function invariant_supplyIsSumOfPayouts() public view { assertEq(layc.totalSupply(), h.sumPayouts()); }
    function invariant_epochMintWithinReward() public view {
        for (uint256 e; e <= h.maxEpoch(); e++) {
            assertLe(h.mintedIn(e), layc.reward(e));
            assertEq(h.mintedIn(e), lrb.paidUnits(e) * lrb.floor(e));
        }
        assertEq(layc.mintedInEpoch(), h.mintedIn(layc.epoch()));
    }
    /// No epoch's floor exceeds MAX_FLOOR, so no epoch mints more than paidUnits × 1 LAYC.
    function invariant_floorBounded() public view {
        for (uint256 e; e <= h.maxEpoch(); e++) {
            assertLe(lrb.floor(e), lrb.MAX_FLOOR());
            assertLe(h.mintedIn(e), lrb.paidUnits(e) * lrb.MAX_FLOOR());
        }
    }
    function invariant_operatorWithinQuarter() public view {
        for (uint256 e; e <= h.maxEpoch(); e++)
            for (uint256 s; s < 6; s++) assertLe(h.mintedTo(e, h.op(s)), layc.reward(e) / 4);
    }
    function invariant_noDoublePay() public view {
        for (uint256 i; i < h.idCount(); i++) assertEq(h.timesPaid(h.ids(i)), 1);
    }
    /// Only a key that was a registered minion of an approved app, not revoked, at the time of the call ever minted.
    function invariant_onlyAttestedMinionsMint() public view { assertFalse(h.foreignSignatureMinted()); }
    function invariant_controllerCannotMint() public view {
        assertFalse(h.controllerMinted());
        assertEq(layc.balanceOf(h.controller()), 0);
        assertEq(layc.owner(), address(lrb));
    }
    /// Every claim pays exactly when the stated rules say it should.
    function invariant_claimOracle() public view { assertFalse(h.claimOracleBroken()); }
}

/// The handler's claims do pay, so the invariants above are not vacuous.
contract HandlerProbe is Test {
    function testHandlerPays() public {
        Handler h = new Handler();
        h.claim(1, 0, 0, false);
        assertEq(h.paidClaims(), 1, "first claim");
        h.advance(11053);
        h.claim(2, 0, 0, false);
        assertEq(h.paidClaims(), 2, "after advance(11053)");
    }
}
