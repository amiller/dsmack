// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import {GuestEscrow} from "../../src/GuestEscrow.sol";
import {LayoverCredit} from "../../src/LayoverCredit.sol";
import {IGuestAttest} from "../../src/GuestEscrow.sol";

/// No guest keys are registered in these checks; only the constructor's registry() binding is needed.
contract NoAttest is IGuestAttest {
    address public immutable registry;
    constructor(address r) { registry = r; }
    function verify(bytes32, bytes calldata) external pure returns (bytes32) { revert("unused"); }
    function assertionEvidence(bytes32) external pure returns (bytes32, bytes32, bytes32, uint64, uint32) { revert("unused"); }
}

/// Symbolic checks for halmos: FOUNDRY_TEST=test/halmos FOUNDRY_DYNAMIC_TEST_LINKING=false halmos (from contracts/).
/// forge test skips check_ functions.
contract SymbolicLayoverCredit is Test {
    LayoverCredit c;
    function setUp() public { c = new LayoverCredit(address(this), 20_990_000e6); }

    /// For every epoch e, reward(e + 1461) == reward(e) / 2 (floor) and reward(e) == INITIAL_REWARD >> (e / 1461).
    function check_rewardHalves(uint256 e) public view {
        vm.assume(e < 2 ** 64);
        assertEq(c.reward(e + 1461), c.reward(e) >> 1);
        assertEq(c.reward(e), c.INITIAL_REWARD() >> (e / 1461));
    }
    /// Any two owner mints in any epoch keep mintedInEpoch ≤ reward(epoch) and totalSupply ≤ CAP.
    function check_mintBounded(uint256 epochs, uint256 a, uint256 b) public {
        vm.assume(epochs < 4);
        for (uint256 i; i < epochs; i++) c.advanceEpoch();
        try c.mint(address(0xA), a) {} catch {}
        try c.mint(address(0xB), b) {} catch {}
        assertLe(c.mintedInEpoch(), c.reward(c.epoch()));
        assertLe(c.totalSupply(), c.CAP());
    }
}

contract SymbolicGuestEscrow is Test {
    GuestEscrow esc;
    LayoverCredit token;
    address buyer = address(0xB1);
    function setUp() public {
        token = new LayoverCredit(address(this), 1_000_000e6);
        NoAttest m = new NoAttest(vm.computeCreateAddress(address(this), 3));
        esc = new GuestEscrow(address(token), address(this), m);
        token.transfer(buyer, 1_000_000e6);
        vm.prank(buyer); token.approve(address(esc), type(uint256).max);
    }
    /// deposit d, accept caps c1 and c2, close the first, wait w, withdraw x with or without releasing it: a successful
    /// withdraw never leaves balance below exposure when the deposit covered both caps, and never pays more than balance.
    function check_withdrawKeepsExposure(uint256 d, uint256 c1, uint256 c2, uint256 w, uint256 x, bool release) public {
        vm.assume(d > 0 && d <= 1_000_000e6 && c1 > 0 && c2 > 0 && c1 <= d && c2 <= d - c1 && w < 365 days);
        vm.startPrank(buyer);
        esc.deposit(d);
        esc.acceptTerms(bytes32(uint256(1)), address(0x22), c1);
        esc.acceptTerms(bytes32(uint256(2)), address(0x22), c2);
        esc.closeTerms(bytes32(uint256(1)));
        vm.warp(block.timestamp + w);
        bytes32[] memory expired = new bytes32[](release ? 1 : 0);
        if (release) expired[0] = bytes32(uint256(1));
        uint256 before = esc.balance(buyer);
        esc.withdraw(x, expired);
        vm.stopPrank();
        assertLe(esc.exposure(buyer), esc.balance(buyer));
        assertEq(esc.balance(buyer), before - x);
        assertEq(token.balanceOf(address(esc)), esc.balance(buyer));
        assertTrue(release ? w >= 1 days && esc.exposure(buyer) == c2 : esc.exposure(buyer) == c1 + c2);
    }
}
