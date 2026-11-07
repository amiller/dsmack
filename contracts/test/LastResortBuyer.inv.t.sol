// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {LastResortBuyer, LayoverCredit} from "../src/LastResortBuyer.sol";
import {Deploy, Signer, LastResortBuyerV2} from "./LastResortBuyer.t.sol";

contract Handler is Signer {
    LastResortBuyer public lrb;
    LayoverCredit public layc;
    address public controller = address(0xC0);
    uint256[2] keys = [uint256(0x3141), 0x2718];
    uint256 public current; // index of the registered minion key
    uint256 pending;
    uint256 public sumPayouts;
    uint256 public paidClaims;
    uint256 public maxEpoch;
    mapping(uint256 => uint256) public mintedIn;
    mapping(uint256 => mapping(address => uint256)) public mintedTo;
    mapping(bytes32 => uint256) public timesPaid;
    bool public foreignSignatureMinted;
    bool public controllerMinted;
    bytes32[] public ids;

    constructor() {
        vm.warp(1000);
        (lrb, layc) = Deploy.issuance(vm, controller, vm.addr(keys[0]));
    }
    function op(uint256 s) public pure returns (address) { return address(uint160(0x100 + s % 6)); }

    function advance(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 3 days));
        try lrb.advance() { maxEpoch = layc.epoch(); } catch {}
    }
    function commitBook(uint256 n, bool honest) external {
        uint256 e = layc.epoch();
        n = bound(n, 0, 40);
        try lrb.commitBook(e, n, bookSig(honest ? keys[current] : 0xBAD, lrb, e, n)) {
            require(honest, "foreign book accepted");
        } catch {}
    }
    function claim(uint256 idSeed, uint256 opSeed, uint256 signer, bool stale) external {
        bytes32 id = bytes32(bound(idSeed, 1, 60));
        (address o, uint256 e) = (op(opSeed), stale && layc.epoch() > 0 ? layc.epoch() - 1 : layc.epoch());
        if (lrb.units(layc.epoch()) == 0) lrb.commitBook(layc.epoch(), 8, bookSig(keys[current], lrb, layc.epoch(), 8));
        uint256 key = [keys[current], keys[current], keys[1 - current], 0xBAD][signer % 4];
        uint256 before = layc.totalSupply();
        try lrb.claim(id, o, e, keccak256(abi.encode(id)), unitSig(key, lrb, id, o, e, keccak256(abi.encode(id)))) {
            uint256 amount = layc.totalSupply() - before;
            if (key != keys[current]) foreignSignatureMinted = true;
            (sumPayouts, mintedIn[e], mintedTo[e][o]) = (sumPayouts + amount, mintedIn[e] + amount, mintedTo[e][o] + amount);
            if (timesPaid[id]++ == 0) ids.push(id);
            paidClaims++;
        } catch {}
    }
    function activateMinion() external {
        try lrb.activateMinion() { current = pending; } catch {}
    }
    function controllerActs(uint256 what) external {
        vm.startPrank(controller);
        uint256 w = what % 5;
        if (w == 0) { pending = 1 - current; lrb.setMinion(vm.addr(keys[pending])); }
        if (w == 1) try layc.mint(controller, 1) { controllerMinted = true; } catch {}
        if (w == 2) try layc.advanceEpoch() { controllerMinted = true; } catch {}
        if (w == 3) try lrb.upgradeTo(address(new LastResortBuyerV2(layc))) {} catch {}
        if (w == 4) lrb.renounceUpgrades();
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
        bytes4[] memory actions = new bytes4[](5);
        (actions[0], actions[1], actions[2], actions[3], actions[4]) =
            (h.advance.selector, h.commitBook.selector, h.claim.selector, h.activateMinion.selector, h.controllerActs.selector);
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
    function invariant_operatorWithinQuarter() public view {
        for (uint256 e; e <= h.maxEpoch(); e++)
            for (uint256 s; s < 6; s++) assertLe(h.mintedTo(e, h.op(s)), layc.reward(e) / 4);
    }
    function invariant_noDoublePay() public view {
        for (uint256 i; i < h.idCount(); i++) assertEq(h.timesPaid(h.ids(i)), 1);
    }
    function invariant_onlyMinionSignatureMints() public view { assertFalse(h.foreignSignatureMinted()); }
    function invariant_controllerCannotMint() public view {
        assertFalse(h.controllerMinted());
        assertEq(layc.balanceOf(h.controller()), 0);
        assertEq(layc.owner(), address(lrb));
    }
    function afterInvariant() public view { assertGt(h.paidClaims(), 0, "handler never paid a unit"); }
}
