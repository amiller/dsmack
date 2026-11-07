// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LastResortBuyer, LayoverCredit} from "../src/LastResortBuyer.sol";

/// LAYC with the predicted proxy as owner, then the implementation, then the proxy: the deploy order of IssuanceLaunch.
library Deploy {
    function issuance(Vm vm, address controller, address kmsRoot) internal returns (LastResortBuyer lrb, LayoverCredit layc) {
        address proxyAt = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 2);
        layc = new LayoverCredit(proxyAt);
        LastResortBuyer impl = new LastResortBuyer(layc, kmsRoot);
        lrb = LastResortBuyer(address(new ERC1967Proxy(address(impl), abi.encodeCall(LastResortBuyer.initialize, (controller)))));
        require(address(lrb) == proxyAt, "predicted proxy");
    }
}

contract LastResortBuyerV2 is LastResortBuyer {
    constructor(LayoverCredit t, address k) LastResortBuyer(t, k) {}
    function version() external pure returns (uint256) { return 2; }
}

/// A hostile upgrade: tries to mint several epochs' rewards in one transaction.
contract GreedyBuyer is LastResortBuyer {
    constructor(LayoverCredit t, address k) LastResortBuyer(t, k) {}
    function drain(address to, uint256 epochs) external {
        for (uint256 i; i < epochs; i++) { token.mint(to, token.reward(token.epoch())); token.advanceEpoch(); }
    }
}

/// Signs dstack GetKey chains the way a dstack 0.5 KMS and guest agent do, with test keys for the KMS root and the app.
abstract contract Minions is Test {
    uint256 constant KMS_PK = 0x6B35;
    uint256 constant APP_PK = 0xA99;
    address constant APP = address(0xA11CE);
    function compressed(uint256 pk) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(pk);
        return abi.encodePacked(bytes1(w.publicKeyY % 2 == 0 ? 0x02 : 0x03), bytes32(w.publicKeyX));
    }
    function link(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v - 27);
    }
    function hexOf(bytes memory data) internal pure returns (bytes memory s) {
        bytes16 alphabet = "0123456789abcdef";
        s = new bytes(data.length * 2);
        for (uint256 i; i < data.length; i++) (s[2 * i], s[2 * i + 1]) = (alphabet[uint8(data[i]) >> 4], alphabet[uint8(data[i]) & 15]);
    }
    /// GetKey(purpose) for a CVM of `app` whose derived key is `minionPk`: (derived pubkey, app pubkey, app sig, kms sig).
    function chain(uint256 kmsPk, address app, uint256 appPk, string memory purpose, uint256 minionPk)
        internal returns (bytes memory d, bytes memory a, bytes memory appSig, bytes memory kmsSig) {
        (d, a) = (compressed(minionPk), compressed(appPk));
        appSig = link(appPk, keccak256(abi.encodePacked(purpose, ":", hexOf(d))));
        kmsSig = link(kmsPk, keccak256(abi.encodePacked("dstack-kms-issued:", app, a)));
    }
    function register(LastResortBuyer lrb, uint256 minionPk) internal returns (address) {
        (bytes memory d, bytes memory a, bytes memory s1, bytes memory s2) = chain(KMS_PK, APP, APP_PK, "layover-minion", minionPk);
        return lrb.registerMinion(APP, d, a, s1, s2);
    }
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

contract LastResortBuyerTest is Minions {
    LastResortBuyer lrb;
    LayoverCredit layc;
    address controller = address(0xC0);
    uint256 minionKey = 0x3141;
    uint256 otherMinion = 0x2718;
    address op = address(0x22);
    bytes32 constant WORK = keccak256("ec-rank window 7");

    function setUp() public {
        vm.warp(1000);
        (lrb, layc) = Deploy.issuance(vm, controller, vm.addr(KMS_PK));
        vm.prank(controller); lrb.approveApp(APP);
        register(lrb, minionKey);
    }
    function book(uint256 n) internal { lrb.commitBook(layc.epoch(), n, bookSig(minionKey, lrb, layc.epoch(), n)); }
    function pay(bytes32 id, address to) internal { lrb.claim(id, to, layc.epoch(), WORK, unitSig(minionKey, lrb, id, to, layc.epoch(), WORK)); }

    function testDeployedState() public {
        (LastResortBuyer fresh, LayoverCredit t) = Deploy.issuance(vm, controller, vm.addr(KMS_PK));
        assertEq(t.owner(), address(fresh));
        assertEq(t.totalSupply(), 0);
        assertEq(fresh.controller(), controller);
        assertEq(address(fresh.token()), address(t));
        assertEq(fresh.kmsRoot(), vm.addr(KMS_PK));
        // Nothing approved, nobody registered: no chain registers and no signature counts.
        assertFalse(fresh.approvedApps(APP));
        (bytes memory d, bytes memory a, bytes memory s1, bytes memory s2) = chain(KMS_PK, APP, APP_PK, "layover-minion", minionKey);
        vm.expectRevert("app not approved"); fresh.registerMinion(APP, d, a, s1, s2);
        bytes memory s = bookSig(minionKey, fresh, 0, 8);
        vm.expectRevert("not minion"); fresh.commitBook(0, 8, s);
    }
    function testNobodyMintsDirectly() public {
        vm.prank(controller); vm.expectRevert("owner only"); layc.mint(controller, 1);
        vm.prank(controller); vm.expectRevert("owner only"); layc.advanceEpoch();
    }
    function testImplementationCannotBeInitialized() public {
        LastResortBuyer impl = new LastResortBuyer(layc, vm.addr(KMS_PK));
        vm.expectRevert("Initializable: contract is already initialized");
        impl.initialize(address(this));
        vm.expectRevert("Initializable: contract is already initialized");
        lrb.initialize(address(this));
    }

    /// Each check registerMinion makes refuses its own bad chain.
    function testRegisterChecks() public {
        uint256 k = 0xA1;
        (bytes memory d, bytes memory a, bytes memory s1, bytes memory s2) = chain(0xBAD, APP, APP_PK, "layover-minion", k);
        vm.expectRevert("kms signature"); lrb.registerMinion(APP, d, a, s1, s2); // signed by another KMS
        (d, a, s1, s2) = chain(KMS_PK, address(0xB0B), APP_PK, "layover-minion", k);
        vm.prank(controller); lrb.approveApp(address(0xB0B));
        vm.expectRevert("kms signature"); lrb.registerMinion(APP, d, a, s1, s2); // KMS signed the app key for another app
        (d, a, s1, s2) = chain(KMS_PK, APP, APP_PK, "ethereum", k);
        vm.expectRevert("app signature"); lrb.registerMinion(APP, d, a, s1, s2); // a key derived for another purpose
        (d, a, s1, s2) = chain(KMS_PK, APP, APP_PK, "layover-minion", k);
        vm.expectRevert("app signature"); lrb.registerMinion(APP, compressed(0xA2), a, s1, s2); // another derived key
        vm.expectRevert("app not approved"); lrb.registerMinion(address(0xC0DE), d, a, s1, s2);
        assertEq(lrb.registerMinion(APP, d, a, s1, s2), vm.addr(k));
        vm.expectRevert("minion key"); lrb.registerMinion(APP, d, a, s1, s2); // already registered
        assertEq(lrb.minionApp(vm.addr(k)), APP);
        assertTrue(lrb.isMinion(vm.addr(k)));
    }
    /// Two registered minions of one app sign interchangeably: one commits the book, the other signs units.
    function testMinionsInterchangeable() public {
        register(lrb, otherMinion);
        book(8);
        lrb.claim("u1", op, 0, WORK, unitSig(otherMinion, lrb, "u1", op, 0, WORK));
        pay("u2", op);
        assertEq(layc.balanceOf(op), 2e6);
    }
    function testRemoveAppStopsItsMinions() public {
        book(8);
        vm.expectRevert("controller only"); lrb.removeApp(APP);
        vm.prank(controller); lrb.removeApp(APP);
        assertFalse(lrb.isMinion(vm.addr(minionKey)));
        bytes memory s = unitSig(minionKey, lrb, "u1", op, 0, WORK);
        vm.expectRevert("not minion"); lrb.claim("u1", op, 0, WORK, s);
        (bytes memory d, bytes memory a, bytes memory s1, bytes memory s2) = chain(KMS_PK, APP, APP_PK, "layover-minion", 0xA1);
        vm.expectRevert("app not approved"); lrb.registerMinion(APP, d, a, s1, s2);
        vm.prank(controller); lrb.approveApp(APP);
        pay("u1", op); // re-approving the app restores its minions
    }
    /// revokeMinion stops one key at once and for good; the app's other minions keep signing.
    function testRevokeMinion() public {
        register(lrb, otherMinion);
        book(8);
        vm.expectRevert("controller only"); lrb.revokeMinion(vm.addr(minionKey));
        vm.prank(controller); lrb.revokeMinion(vm.addr(minionKey));
        bytes memory s = unitSig(minionKey, lrb, "u1", op, 0, WORK);
        vm.expectRevert("not minion"); lrb.claim("u1", op, 0, WORK, s);
        lrb.claim("u1", op, 0, WORK, unitSig(otherMinion, lrb, "u1", op, 0, WORK));
        (bytes memory d, bytes memory a, bytes memory s1, bytes memory s2) = chain(KMS_PK, APP, APP_PK, "layover-minion", minionKey);
        vm.expectRevert("minion key"); lrb.registerMinion(APP, d, a, s1, s2);
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
        book(8); // reward / 8 is 898.375 LAYC; a unit pays at most MAX_FLOOR
        assertEq(lrb.floor(0), 1e6);
        pay("u1", op);
        assertEq(layc.balanceOf(op), 1e6);
        assertEq(layc.totalSupply(), 1e6);
        bytes memory s = unitSig(minionKey, lrb, "u1", op, 0, WORK);
        vm.expectRevert("unit paid"); lrb.claim("u1", op, 0, WORK, s);
    }
    function testFloorBounded() public {
        book(4);
        assertEq(lrb.floor(0), lrb.MAX_FLOOR());
        for (uint256 i; i < 4; i++) pay(bytes32(i + 1), address(uint160(0x100 + i)));
        assertEq(layc.totalSupply(), 4e6);
        vm.warp(1000 + 1 days); lrb.advance();
        book(10_000); // 7,187 / 10,000 = 0.7187 LAYC a unit
        assertEq(lrb.floor(1), 718_700);
    }
    function testBookWindow() public {
        vm.warp(1000 + 2 hours + 1);
        bytes memory b = bookSig(minionKey, lrb, 0, 8);
        vm.expectRevert("book window"); lrb.commitBook(0, 8, b);
        vm.warp(1000 + 1 days + 5 hours); lrb.advance();
        assertEq(layc.epochStart(), 1000 + 1 days + 5 hours);
        vm.warp(1000 + 1 days + 7 hours);
        book(8);
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
        book(7_187); // floor 1 LAYC: 1,796 units per operator fit in 1,796.75
        for (uint256 i; i < 1_796; i++) pay(bytes32(i + 1), op);
        bytes memory s = unitSig(minionKey, lrb, "last", op, 0, WORK);
        vm.expectRevert("operator cap"); lrb.claim("last", op, 0, WORK, s);
        pay("last", address(0x23));
        assertEq(layc.balanceOf(op), 1_796e6);
    }
    function testBookFullAndUnspentNeverMinted() public {
        book(5); // floor 1 LAYC
        for (uint256 i; i < 4; i++) pay(bytes32(i + 1), address(uint160(0x100 + i)));
        vm.warp(1000 + 1 days);
        lrb.advance();
        assertEq(layc.totalSupply(), 4e6); // the fifth unit was never claimed and is not minted later
        bytes memory s = unitSig(minionKey, lrb, bytes32(uint256(5)), address(0x105), 0, WORK);
        vm.expectRevert("not current epoch"); lrb.claim(bytes32(uint256(5)), address(0x105), 0, WORK, s);
    }
    function testBookCountsUnits() public {
        vm.warp(1000 + 1 days); lrb.advance();
        book(4);
        for (uint256 i; i < 4; i++) pay(bytes32(i + 1), address(uint160(0x100 + i)));
        bytes memory s = unitSig(minionKey, lrb, "u5", address(0x200), 1, WORK);
        vm.expectRevert("book full"); lrb.claim("u5", address(0x200), 1, WORK, s);
        assertEq(layc.totalSupply(), 4e6);
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
        vm.prank(controller); vm.expectRevert("controller only"); lrb.approveApp(address(1));
    }
    function testUpgradeKeepsStateThenRenounce() public {
        book(8); pay("u1", op);
        LastResortBuyerV2 v2 = new LastResortBuyerV2(layc, vm.addr(KMS_PK));
        vm.expectRevert("controller only"); lrb.upgradeTo(address(v2));
        vm.prank(controller); lrb.upgradeTo(address(v2));
        assertEq(LastResortBuyerV2(address(lrb)).version(), 2);
        assertTrue(lrb.paid("u1"));
        assertEq(lrb.paidTo(0, op), 1e6);
        assertTrue(lrb.isMinion(vm.addr(minionKey)));
        vm.expectRevert("controller only"); lrb.renounceUpgrades();
        vm.prank(controller); lrb.renounceUpgrades();
        LastResortBuyerV2 v3 = new LastResortBuyerV2(layc, vm.addr(KMS_PK));
        vm.prank(controller); vm.expectRevert("upgrades renounced"); lrb.upgradeTo(address(v3));
        vm.prank(controller); lrb.revokeMinion(vm.addr(minionKey)); // revocation survives the renounce
    }
    function testHostileUpgradeBoundedByLAYC() public {
        GreedyBuyer g = new GreedyBuyer(layc, vm.addr(KMS_PK));
        vm.prank(controller); lrb.upgradeTo(address(g));
        vm.expectRevert("period not over"); GreedyBuyer(address(lrb)).drain(address(0xBAD), 2);
        vm.expectRevert("epoch reward"); vm.prank(address(lrb)); layc.mint(address(0xBAD), 7_187e6 + 1);
    }
    function testUpgradeMustKeepToken() public {
        LastResortBuyer other = new LastResortBuyer(new LayoverCredit(address(1)), vm.addr(KMS_PK));
        vm.prank(controller); vm.expectRevert("token"); lrb.upgradeTo(address(other));
    }
}

/// The real GetKey chain from a live dstack-0.5.8 CVM on Phala's Base KMS (fixtures/dstack/kms-chain-base-20260916.json),
/// against a LastResortBuyer pinned to the Base KMS root: the chain reaches the root, and the key is refused only because
/// it was derived for purpose "ethereum", not PURPOSE.
contract LastResortBuyerRealChainTest is Test {
    function testRealBaseKmsChain() public {
        string memory j = vm.readFile("fixtures/dstack/kms-chain-base-20260916.json");
        address app = vm.parseJsonAddress(j, ".appId");
        (LastResortBuyer lrb,) = Deploy.issuance(vm, address(this), vm.parseJsonAddress(j, ".kmsRoot"));
        lrb.approveApp(app);
        lrb.approveApp(address(0x2a45));
        (bytes memory d, bytes memory a) = (vm.parseJsonBytes(j, ".derivedPubkey"), vm.parseJsonBytes(j, ".appPubkey"));
        (bytes memory s1, bytes memory s2) = (vm.parseJsonBytes(j, ".appSignature"), vm.parseJsonBytes(j, ".kmsSignature"));
        vm.expectRevert("app signature"); lrb.registerMinion(app, d, a, s1, s2);
        vm.expectRevert("kms signature"); lrb.registerMinion(address(0x2a45), d, a, s1, s2);
    }
}
