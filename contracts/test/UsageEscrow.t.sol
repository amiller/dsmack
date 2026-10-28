// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {UsageEscrow} from "../src/UsageEscrow.sol";

contract EscrowPayee {
    UsageEscrow escrow;
    bool public reject;
    bool public reentryPaid;
    uint256 public received;

    constructor(UsageEscrow e) {
        escrow = e;
    }

    function setReject(bool r) external {
        reject = r;
    }

    function withdraw() external {
        escrow.withdraw();
    }

    receive() external payable {
        require(!reject, "reject");
        received += msg.value;
        // Attempt a second withdrawal during the external call.
        (reentryPaid,) = address(escrow).call(abi.encodeCall(escrow.withdraw, ()));
    }
}

contract UsageEscrowTest is Test {
    UsageEscrow e;
    bytes32 constant NODE = keccak256("compute run");
    bytes32 constant BUYER_KEY = keccak256("fresh buyer Ed25519 public key");
    uint256 constant GUEST_KEY = 0xA77E57;
    uint256 constant FORGED_KEY = 0xBAD;
    address constant BUYER = address(0xB0B);
    address constant OPERATOR = address(0xA11CE);

    event Purchase(
        uint256 indexed purchaseId,
        bytes32 indexed node,
        address indexed payer,
        bytes32 buyerKey,
        uint8 unit,
        uint128 amount,
        uint128 price,
        uint64 expires
    );

    function setUp() public {
        vm.chainId(84532);
        vm.warp(120000);
        vm.deal(address(this), 100 ether);
        vm.deal(BUYER, 100 ether);
        e = new UsageEscrow(address(this));
        register(NODE, OPERATOR, 1, 1000, 100);
    }

    function register(bytes32 node, address operator, uint8 unit, uint128 floor, uint128 target) internal {
        e.registerNode(
            node,
            operator,
            vm.addr(GUEST_KEY),
            keccak256("attested binding"),
            unit,
            floor,
            target,
            uint64(block.timestamp + 7 days)
        );
    }

    function buy(uint128 amount) internal returns (uint256 id) {
        uint256 price = e.quote(NODE);
        vm.prank(BUYER);
        return e.buy{value: uint256(amount) * price}(NODE, 1, amount, BUYER_KEY);
    }

    function receipt(uint256 id, uint64 seq, uint128 used, bool finalReceipt)
        internal
        view
        returns (UsageEscrow.Receipt memory)
    {
        return UsageEscrow.Receipt(id, seq, used, uint64(block.timestamp), finalReceipt);
    }

    function submit(UsageEscrow.Receipt memory r, uint256 key) internal {
        submit(r, key, "");
    }

    function submit(UsageEscrow.Receipt memory r, uint256 key, string memory error) internal {
        UsageEscrow.Receipt[] memory receipts = new UsageEscrow.Receipt[](1);
        bytes[] memory sigs = new bytes[](1);
        receipts[0] = r;
        (uint8 v, bytes32 sigR, bytes32 sigS) = vm.sign(key, e.receiptDigest(r));
        sigs[0] = abi.encodePacked(sigR, sigS, v);
        if (bytes(error).length > 0) vm.expectRevert(bytes(error));
        e.settle(receipts, sigs);
    }

    function tick() internal {
        vm.warp(block.timestamp + 60);
    }

    function testBuyPinsTermsAndEmitsPurchase() public {
        vm.expectEmit(true, true, true, true);
        emit Purchase(1, NODE, BUYER, BUYER_KEY, 1, 100, 1000, uint64(block.timestamp + 3600));
        uint256 id = buy(100);
        UsageEscrow.PurchaseData memory p = e.getPurchase(id);
        assertEq(p.payer, BUYER);
        assertEq(p.receiptSigner, vm.addr(GUEST_KEY));
        assertEq(p.operator, OPERATOR);
        assertEq(p.buyerKey, BUYER_KEY);
        assertEq(p.price, 1000);
        assertEq(address(e).balance, 100000);
    }

    function testPriceRisesUnderLoadAndFallsWhenIdle() public {
        buy(200);
        assertEq(e.quote(NODE), 1000); // no same-epoch movement
        tick();
        assertEq(e.quote(NODE), 1125);
        e.checkpoint(NODE);
        assertEq(e.getNode(NODE).price, 1125);
        tick();
        assertEq(e.quote(NODE), 1000);
    }

    function testPriceAtTargetUnchangedAndFloorSurvivesIdleEpochs() public {
        buy(100);
        tick();
        assertEq(e.quote(NODE), 1000);
        vm.warp(block.timestamp + 365 days);
        e.checkpoint(NODE);
        assertEq(e.quote(NODE), 1000);
    }

    function testPriceCeilingStepCapAndLongIdleDecay() public {
        for (uint256 i; i < 40; ++i) {
            uint256 beforePrice = e.quote(NODE);
            buy(600); // 3x full capacity, capped utilization
            tick();
            uint256 afterPrice = e.quote(NODE);
            assertLe(afterPrice, beforePrice + beforePrice / 8);
            assertLe(afterPrice, 16000);
        }
        assertEq(e.quote(NODE), 16000);
        e.checkpoint(NODE);
        vm.warp(block.timestamp + 2 days);
        assertEq(e.quote(NODE), 1000);
        e.checkpoint(NODE);
        assertEq(e.getNode(NODE).price, 1000);
    }

    function testSeparateNodesHaveIndependentPricesAndUnits() public {
        bytes32 relay = keccak256("relay run");
        register(relay, OPERATOR, 0, 1000, 300 * 1024 * 1024);
        buy(200);
        tick();
        assertEq(e.quote(NODE), 1125);
        assertEq(e.quote(relay), 1000);
        uint256 id = e.buy{value: uint256(64 * 1024 * 1024) * 1000}(relay, 0, 64 * 1024 * 1024, BUYER_KEY);
        submit(receipt(id, 1, 1024, true), GUEST_KEY);
        assertEq(e.credits(OPERATOR), 1024000);
    }

    function testSettleCumulativeUsageThenFinalRefundAndWithdraw() public {
        uint256 id = buy(100);
        submit(receipt(id, 1, 25, false), GUEST_KEY);
        submit(receipt(id, 2, 60, true), GUEST_KEY);
        assertEq(e.credits(OPERATOR), 60000);
        assertEq(e.credits(BUYER), 40000);
        assertTrue(e.getPurchase(id).closed);
        uint256 beforeBalance = OPERATOR.balance;
        vm.prank(OPERATOR);
        e.withdraw();
        assertEq(OPERATOR.balance - beforeBalance, 60000);
        vm.prank(BUYER);
        e.withdraw();
        assertEq(address(e).balance, 0);
    }

    function testPremiumLockedAndUnusedPremiumRefunded() public {
        buy(200);
        tick();
        uint256 id = buy(100);
        assertEq(e.getPurchase(id).price, 1125);
        submit(receipt(id, 1, 40, true), GUEST_KEY);
        assertEq(e.credits(OPERATOR), 40000);
        assertEq(e.lockedPremium(), 5000);
        assertEq(e.credits(BUYER), 67500);
    }

    function testRefundAfterGracePaysPayerNotCaller() public {
        uint256 id = buy(100);
        submit(receipt(id, 1, 10, false), GUEST_KEY);
        UsageEscrow.PurchaseData memory p = e.getPurchase(id);
        vm.warp(p.expires + 3600);
        vm.prank(address(0x1234));
        e.refund(id);
        assertEq(e.credits(BUYER), 90000);
        assertEq(e.credits(OPERATOR), 10000);
        assertEq(e.credits(address(0x1234)), 0);
        vm.expectRevert(bytes("purchase closed or unknown"));
        e.refund(id);
    }

    function testSettlementDeadlineAndRefundBoundary() public {
        uint256 id = buy(100);
        uint64 expires = e.getPurchase(id).expires;
        vm.warp(expires + 3599);
        UsageEscrow.Receipt memory r = UsageEscrow.Receipt(id, 1, 40, expires, false);
        submit(r, GUEST_KEY);
        vm.expectRevert(bytes("refund not ready"));
        e.refund(id);
        vm.warp(expires + 3600);
        r.sequence = 2;
        submit(r, GUEST_KEY, "settlement expired");
        e.refund(id);
        assertEq(e.credits(BUYER), 60000);
    }

    function testDoubleSettlementAndFinalReplayFail() public {
        uint256 id = buy(100);
        UsageEscrow.Receipt memory r = receipt(id, 1, 10, false);
        submit(r, GUEST_KEY);
        submit(r, GUEST_KEY, "usage or sequence");
        r.sequence = 2;
        r.finalReceipt = true;
        submit(r, GUEST_KEY);
        submit(r, GUEST_KEY, "purchase closed or unknown");
    }

    function testForgedAndUnregisteredReceiptKeysFail() public {
        uint256 id = buy(100);
        submit(receipt(id, 1, 100, true), FORGED_KEY, "receipt signer");
        assertEq(e.credits(OPERATOR), 0);
        assertEq(e.getPurchase(id).used, 0);
        submit(receipt(id + 1, 1, 100, true), GUEST_KEY, "purchase closed or unknown");
    }

    function testSignatureCannotCrossPurchaseOrContractDomain() public {
        uint256 first = buy(100);
        uint256 second = buy(100);
        UsageEscrow.Receipt memory r = receipt(first, 1, 40, false);
        (uint8 v, bytes32 sigR, bytes32 sigS) = vm.sign(GUEST_KEY, e.receiptDigest(r));
        UsageEscrow.Receipt[] memory receipts = new UsageEscrow.Receipt[](1);
        bytes[] memory sigs = new bytes[](1);
        receipts[0] = receipt(second, 1, 40, false);
        sigs[0] = abi.encodePacked(sigR, sigS, v);
        vm.expectRevert(bytes("receipt signer"));
        e.settle(receipts, sigs);
        UsageEscrow other = new UsageEscrow(address(this));
        other.registerNode(
            NODE, OPERATOR, vm.addr(GUEST_KEY), keccak256("other"), 1, 1000, 100, uint64(block.timestamp + 1 days)
        );
        other.buy{value: 100000}(NODE, 1, 100, BUYER_KEY);
        receipts[0] = r;
        vm.expectRevert(bytes("receipt signer"));
        other.settle(receipts, sigs);
    }

    function testOverBudgetDecreasingUsageAndTimeFail() public {
        uint256 id = buy(100);
        submit(receipt(id, 1, 101, false), GUEST_KEY, "usage or sequence");
        tick();
        submit(receipt(id, 1, 40, false), GUEST_KEY);
        submit(receipt(id, 2, 39, false), GUEST_KEY, "usage or sequence");
        UsageEscrow.Receipt memory r = receipt(id, 2, 50, false);
        r.endedAt--;
        submit(r, GUEST_KEY, "receipt time");
        r.endedAt = uint64(block.timestamp + 1);
        submit(r, GUEST_KEY, "receipt time");
        vm.warp(e.getPurchase(id).expires + 1);
        r.endedAt = uint64(block.timestamp);
        submit(r, GUEST_KEY, "receipt time");
    }

    function testReceiptBeforePurchaseFailsAndNoUsageFinalRefundsAll() public {
        uint256 id = buy(100);
        UsageEscrow.Receipt memory r = receipt(id, 1, 0, true);
        r.endedAt--;
        submit(r, GUEST_KEY, "receipt time");
        r.endedAt++;
        submit(r, GUEST_KEY);
        assertEq(e.credits(BUYER), 100000);
        assertEq(e.credits(OPERATOR), 0);
    }

    function testBatchIsAtomicAndSupportsIncreasingReceipts() public {
        uint256 id = buy(100);
        UsageEscrow.Receipt[] memory rs = new UsageEscrow.Receipt[](2);
        bytes[] memory sigs = new bytes[](2);
        rs[0] = receipt(id, 1, 10, false);
        rs[1] = receipt(id, 2, 60, true);
        for (uint256 i; i < 2; ++i) {
            (uint8 v, bytes32 sigR, bytes32 sigS) = vm.sign(i == 0 ? GUEST_KEY : FORGED_KEY, e.receiptDigest(rs[i]));
            sigs[i] = abi.encodePacked(sigR, sigS, v);
        }
        vm.expectRevert(bytes("receipt signer"));
        e.settle(rs, sigs);
        assertEq(e.getPurchase(id).used, 0);
        (uint8 finalV, bytes32 finalR, bytes32 finalS) = vm.sign(GUEST_KEY, e.receiptDigest(rs[1]));
        sigs[1] = abi.encodePacked(finalR, finalS, finalV);
        e.settle(rs, sigs);
        assertEq(e.credits(OPERATOR), 60000);
        assertEq(e.credits(BUYER), 40000);
    }

    function testRegistrationOwnerOnlyAndRunCannotBeReplaced() public {
        vm.prank(BUYER);
        vm.expectRevert(bytes("owner only"));
        e.registerNode(
            keccak256("fake"),
            BUYER,
            vm.addr(FORGED_KEY),
            bytes32(uint256(1)),
            1,
            1,
            1,
            uint64(block.timestamp + 1 days)
        );
        vm.expectRevert(bytes("node exists or zero"));
        register(NODE, BUYER, 1, 1, 1);
        vm.expectRevert(bytes("unknown node"));
        e.buy{value: 1}(keccak256("unknown"), 1, 1, BUYER_KEY);
    }

    function testBuyRejectsWrongPriceUnitBudgetAndExpiredRun() public {
        vm.expectRevert(bytes("exact price"));
        e.buy{value: 999}(NODE, 1, 1, BUYER_KEY);
        vm.expectRevert(bytes("unit"));
        e.buy{value: 1000}(NODE, 0, 1, BUYER_KEY);
        vm.expectRevert(bytes("amount"));
        e.buy(NODE, 1, 0, BUYER_KEY);
        vm.expectRevert(bytes("amount"));
        e.buy(NODE, 1, 601, BUYER_KEY);
        vm.expectRevert(bytes("buyer key"));
        e.buy{value: 1000}(NODE, 1, 1, bytes32(0));
        vm.warp(e.getNode(NODE).runExpires);
        vm.expectRevert(bytes("run expired"));
        e.buy{value: 1000}(NODE, 1, 1, BUYER_KEY);
    }

    function testStaleQuoteRevertsAndExpiryClampsToRun() public {
        uint256 oldPrice = e.quote(NODE);
        buy(200);
        tick();
        vm.expectRevert(bytes("exact price"));
        e.buy{value: oldPrice * 100}(NODE, 1, 100, BUYER_KEY);
        vm.warp(e.getNode(NODE).runExpires - 30);
        uint256 id = buy(100);
        assertEq(e.getPurchase(id).expires, e.getNode(NODE).runExpires);
    }

    function testSelfDealingCannotExtractPremiumOrCreateProfit() public {
        register(keccak256("self"), BUYER, 1, 1000, 100);
        bytes32 node = keccak256("self");
        uint256 spent;
        for (uint256 i; i < 30; ++i) {
            uint256 cost = uint256(e.quote(node)) * 200;
            spent += cost;
            vm.prank(BUYER);
            uint256 id = e.buy{value: cost}(node, 1, 200, BUYER_KEY);
            submit(receipt(id, 1, 200, true), GUEST_KEY);
            tick();
        }
        assertEq(e.credits(BUYER), 30 * 200 * 1000);
        assertEq(spent - e.credits(BUYER), e.lockedPremium());
        assertGt(e.lockedPremium(), 0);
        vm.prank(BUYER);
        e.withdraw();
        assertEq(address(e).balance, e.lockedPremium());
        vm.expectRevert(bytes("no credit"));
        e.withdraw(); // owner has no premium withdrawal
    }

    function testUnconsumedSelfReservationsCanOnlyMovePriceWithinBounds() public {
        bytes32 node = keccak256("refundable self reservation");
        register(node, BUYER, 1, 1000, 100);
        for (uint256 i; i < 30; ++i) {
            uint256 beforeBalance = BUYER.balance;
            uint256 price = e.quote(node);
            vm.prank(BUYER);
            uint256 id = e.buy{value: price * 200}(node, 1, 200, BUYER_KEY);
            submit(receipt(id, 1, 0, true), GUEST_KEY);
            vm.prank(BUYER);
            e.withdraw();
            assertEq(BUYER.balance, beforeBalance);
            tick();
            assertLe(e.quote(node), price + price / 8);
            assertLe(e.quote(node), 16000);
        }
        assertEq(e.quote(node), 16000);
        assertEq(e.lockedPremium(), 0);
        assertEq(address(e).balance, 0);
    }

    function testWithdrawalFailurePreservesCreditAndReentryCannotPayTwice() public {
        EscrowPayee payee = new EscrowPayee(e);
        bytes32 node = keccak256("contract payee");
        register(node, address(payee), 1, 1000, 100);
        uint256 id = e.buy{value: 100000}(node, 1, 100, BUYER_KEY);
        submit(receipt(id, 1, 100, true), GUEST_KEY);
        payee.setReject(true);
        vm.expectRevert(bytes("withdraw failed"));
        payee.withdraw();
        assertEq(e.credits(address(payee)), 100000);
        payee.setReject(false);
        payee.withdraw();
        assertEq(payee.received(), 100000);
        assertFalse(payee.reentryPaid());
        assertEq(e.credits(address(payee)), 0);
    }

    function testDeploymentRejectsMainnet() public {
        vm.chainId(8453);
        vm.expectRevert(bytes("Base Sepolia only"));
        new UsageEscrow(address(this));
    }
}
