// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LastResortBuyer, LayoverCredit} from "../src/LastResortBuyer.sol";

/// LAYC with the predicted proxy as owner, then the implementation, then the proxy: the deploy order of IssuanceLaunch.
library Deploy {
    function issuance(Vm vm, address controller, address minion) internal returns (LastResortBuyer lrb, LayoverCredit layc) {
        address proxyAt = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 2);
        layc = new LayoverCredit(proxyAt);
        LastResortBuyer impl = new LastResortBuyer(layc);
        lrb = LastResortBuyer(address(new ERC1967Proxy(address(impl), abi.encodeCall(LastResortBuyer.initialize, (controller, minion)))));
        require(address(lrb) == proxyAt, "predicted proxy");
    }
}

contract LastResortBuyerV2 is LastResortBuyer {
    constructor(LayoverCredit t) LastResortBuyer(t) {}
    function version() external pure returns (uint256) { return 2; }
}

/// A hostile upgrade: tries to mint several epochs' rewards in one transaction.
contract GreedyBuyer is LastResortBuyer {
    constructor(LayoverCredit t) LastResortBuyer(t) {}
    function drain(address to, uint256 epochs) external {
        for (uint256 i; i < epochs; i++) { token.mint(to, token.reward(token.epoch())); token.advanceEpoch(); }
    }
}

abstract contract Signer is Test {
    function sig(uint256 key, LastResortBuyer lrb, bytes32 structHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, keccak256(abi.encodePacked("\x19\x01", lrb.DOMAIN_SEPARATOR(), structHash)));
        return abi.encodePacked(r, s, v);
    }
    function bookSig(uint256 key, LastResortBuyer lrb, uint256 e, uint256 n) internal view returns (bytes memory) {
        return sig(key, lrb, keccak256(abi.encode(keccak256("Book(uint256 epoch,uint256 units)"), e, n)));
    }
    function unitSig(uint256 key, LastResortBuyer lrb, bytes32 id, address op, uint256 e, bytes32 w) internal view returns (bytes memory) {
        return sig(key, lrb, keccak256(abi.encode(keccak256("Unit(bytes32 unitId,address operator,uint256 epoch,bytes32 workDigest)"), id, op, e, w)));
    }
}

contract LastResortBuyerTest is Signer {
    LastResortBuyer lrb;
    LayoverCredit layc;
    address controller = address(0xC0);
    uint256 minionKey = 0x3141;
    address op = address(0x22);
    bytes32 constant WORK = keccak256("ec-rank window 7");

    function setUp() public {
        vm.warp(1000);
        (lrb, layc) = Deploy.issuance(vm, controller, vm.addr(minionKey));
    }
    function book(uint256 n) internal { lrb.commitBook(layc.epoch(), n, bookSig(minionKey, lrb, layc.epoch(), n)); }
    function pay(bytes32 id, address to) internal { lrb.claim(id, to, layc.epoch(), WORK, unitSig(minionKey, lrb, id, to, layc.epoch(), WORK)); }

    function testDeployedState() public view {
        assertEq(layc.owner(), address(lrb));
        assertEq(layc.totalSupply(), 0);
        assertEq(lrb.controller(), controller);
        assertEq(lrb.minion(), vm.addr(minionKey));
        assertEq(address(lrb.token()), address(layc));
    }
    function testNobodyMintsDirectly() public {
        vm.prank(controller); vm.expectRevert("owner only"); layc.mint(controller, 1);
        vm.prank(controller); vm.expectRevert("owner only"); layc.advanceEpoch();
    }
    function testImplementationCannotBeInitialized() public {
        LastResortBuyer impl = new LastResortBuyer(layc);
        vm.expectRevert("Initializable: contract is already initialized");
        impl.initialize(address(this), address(this));
        vm.expectRevert("Initializable: contract is already initialized");
        lrb.initialize(address(this), address(this));
    }
    function testAdvanceOncePerDay() public {
        vm.expectRevert("period not over"); lrb.advance();
        vm.warp(1000 + 1 days);
        lrb.advance();
        assertEq(layc.epoch(), 1);
        vm.warp(1000 + 2 days - 1);
        vm.expectRevert("period not over"); lrb.advance();
        vm.warp(1000 + 5 days);
        lrb.advance();
        vm.expectRevert("period not over"); lrb.advance(); // no catch-up after a gap
        assertEq(layc.epoch(), 2);
    }
    function testUnitPaidFloorOnce() public {
        book(8);
        assertEq(lrb.floor(0), 7_187e6 / 8);
        pay("u1", op);
        assertEq(layc.balanceOf(op), 898_375_000);
        assertEq(layc.totalSupply(), 898_375_000);
        bytes memory s = unitSig(minionKey, lrb, "u1", op, 0, WORK);
        vm.expectRevert("unit paid"); lrb.claim("u1", op, 0, WORK, s);
    }
    function testBookOncePerEpochAndRequired() public {
        bytes memory s = unitSig(minionKey, lrb, "u1", op, 0, WORK);
        vm.expectRevert("no book"); lrb.claim("u1", op, 0, WORK, s);
        uint256[3] memory bad = [uint256(0), 3, 7_187e6 + 1]; // under 4 units no unit fits the operator cap; floor 0
        for (uint256 i; i < 3; i++) {
            bytes memory b = bookSig(minionKey, lrb, 0, bad[i]);
            vm.expectRevert(bytes("book")); lrb.commitBook(0, bad[i], b);
        }
        book(8);
        bytes memory again = bookSig(minionKey, lrb, 0, 9);
        vm.expectRevert(bytes("book")); lrb.commitBook(0, 9, again);
    }
    function testOnlyMinionSignatures() public {
        bytes memory b = bookSig(0xBAD, lrb, 0, 8);
        vm.expectRevert("not minion"); lrb.commitBook(0, 8, b);
        book(8);
        bytes memory s = unitSig(0xBAD, lrb, "u1", op, 0, WORK);
        vm.expectRevert("not minion"); lrb.claim("u1", op, 0, WORK, s);
        s = unitSig(minionKey, lrb, "u1", op, 0, WORK);
        vm.expectRevert("not minion"); lrb.claim("u1", address(0x23), 0, WORK, s); // operator swapped
        vm.expectRevert("not minion"); lrb.claim("u1", op, 0, keccak256("other"), s); // work digest swapped
    }
    function testOperatorCapQuarterOfReward() public {
        book(8); // floor 898.375: two units per operator fit in 1,796.75
        pay("u1", op); pay("u2", op);
        bytes memory s = unitSig(minionKey, lrb, "u3", op, 0, WORK);
        vm.expectRevert("operator cap"); lrb.claim("u3", op, 0, WORK, s);
        pay("u3", address(0x23));
        assertEq(layc.balanceOf(op), 7_187e6 / 4);
    }
    function testBookFullAndUnspentNeverMinted() public {
        book(5); // floor 1,437.4
        for (uint256 i; i < 4; i++) pay(bytes32(i + 1), address(uint160(0x100 + i)));
        vm.warp(1000 + 1 days);
        lrb.advance();
        assertEq(layc.totalSupply(), 4 * 1_437.4e6); // the fifth unit was never claimed and is not minted later
        bytes memory s = unitSig(minionKey, lrb, bytes32(uint256(5)), address(0x105), 0, WORK);
        vm.expectRevert("not current epoch"); lrb.claim(bytes32(uint256(5)), address(0x105), 0, WORK, s);
    }
    function testBookCountsUnits() public {
        vm.warp(1000 + 1 days); lrb.advance();
        book(4);
        for (uint256 i; i < 4; i++) pay(bytes32(i + 1), address(uint160(0x100 + i)));
        bytes memory s = unitSig(minionKey, lrb, "u5", address(0x200), 1, WORK);
        vm.expectRevert("book full"); lrb.claim("u5", address(0x200), 1, WORK, s);
        assertEq(layc.totalSupply(), 7_187e6);
    }
    function testControllerSetsMinion() public {
        vm.expectRevert("controller only"); lrb.setMinion(address(1));
        vm.prank(controller); lrb.setMinion(vm.addr(0xBEEF));
        assertEq(lrb.minion(), vm.addr(minionKey));
        vm.warp(1000 + 1 days - 1);
        vm.expectRevert("no minion due"); lrb.activateMinion();
        bytes memory b = bookSig(0xBEEF, lrb, 0, 8);
        vm.expectRevert("not minion"); lrb.commitBook(0, 8, b);
        vm.warp(1000 + 1 days);
        lrb.activateMinion();
        assertEq(lrb.minion(), vm.addr(0xBEEF));
        b = bookSig(minionKey, lrb, 0, 8);
        vm.expectRevert("not minion"); lrb.commitBook(0, 8, b);
        lrb.commitBook(0, 8, bookSig(0xBEEF, lrb, 0, 8));
        vm.expectRevert("no minion due"); lrb.activateMinion();
    }
    function testControllerTwoStep() public {
        address safe = address(0x5AFE);
        vm.expectRevert("controller only"); lrb.transferController(safe);
        vm.prank(controller); lrb.transferController(safe);
        assertEq(lrb.controller(), controller);
        vm.expectRevert("pending controller only"); lrb.acceptController();
        vm.prank(safe); lrb.acceptController();
        assertEq(lrb.controller(), safe);
        assertEq(lrb.pendingController(), address(0));
        vm.prank(controller); vm.expectRevert("controller only"); lrb.setMinion(address(1));
    }
    function testUpgradeKeepsStateThenRenounce() public {
        book(8); pay("u1", op);
        LastResortBuyerV2 v2 = new LastResortBuyerV2(layc);
        vm.expectRevert("controller only"); lrb.upgradeTo(address(v2));
        vm.prank(controller); lrb.upgradeTo(address(v2));
        assertEq(LastResortBuyerV2(address(lrb)).version(), 2);
        assertTrue(lrb.paid("u1"));
        assertEq(lrb.paidTo(0, op), 898_375_000);
        vm.expectRevert("controller only"); lrb.renounceUpgrades();
        vm.prank(controller); lrb.renounceUpgrades();
        LastResortBuyerV2 v3 = new LastResortBuyerV2(layc);
        vm.prank(controller); vm.expectRevert("upgrades renounced"); lrb.upgradeTo(address(v3));
        vm.prank(controller); lrb.setMinion(address(7)); // key rotation survives the renounce
    }
    function testHostileUpgradeBoundedByLAYC() public {
        GreedyBuyer g = new GreedyBuyer(layc);
        vm.prank(controller); lrb.upgradeTo(address(g));
        vm.expectRevert("period not over"); GreedyBuyer(address(lrb)).drain(address(0xBAD), 2);
        vm.expectRevert("epoch reward"); vm.prank(address(lrb)); layc.mint(address(0xBAD), 7_187e6 + 1);
    }
    function testUpgradeMustKeepToken() public {
        LastResortBuyer other = new LastResortBuyer(new LayoverCredit(address(1)));
        vm.prank(controller); vm.expectRevert("token"); lrb.upgradeTo(address(other));
    }
}
