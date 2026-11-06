// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import "../src/UsageEscrow.sol";

contract MockUSDC {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address to, uint256 amount) external returns (bool) { allowance[msg.sender][to] = amount; return true; }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount; balanceOf[from] -= amount; balanceOf[to] += amount; return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true;
    }
}
contract UsageEscrowTest is Test {
    UsageEscrow rail;
    MockUSDC usdc;
    address user = address(0x11);
    address other = address(0x12);
    address operator = address(0x22);
    uint256 brokerKey = 123;
    function setUp() public {
        vm.warp(30 weeks);
        usdc = new MockUSDC(); rail = new UsageEscrow(address(usdc), address(this));
        rail.registerBroker(vm.addr(brokerKey));
        fund(user, 10e6); fund(other, 100e6);
    }
    function fund(address who, uint256 amount) internal {
        usdc.mint(who, amount); vm.startPrank(who);
        usdc.approve(address(rail), amount); rail.deposit(amount); vm.stopPrank();
    }
    function signature(address who, UsageEscrow.Claim memory c) internal view returns(bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(brokerKey, rail.claimDigest(who,c)); return abi.encodePacked(r,s,v);
    }
    function testDepositAndCumulativeDebitClaim() public {
        assertEq(rail.balance(user), 10e6);
        UsageEscrow.Claim memory c = UsageEscrow.Claim(operator, 2e6, 29);
        rail.claim(user,c,signature(user,c));
        assertEq(usdc.balanceOf(operator),2e6); assertEq(rail.balance(user),8e6);
        bytes memory sig = signature(user,c);
        vm.expectRevert("claim replay"); rail.claim(user,c,sig);
        c.cumulativeOwed = 3e6;
        rail.claim(user,c,signature(user,c));
        assertEq(usdc.balanceOf(operator),3e6);
    }
    function testOverClaimCannotUseAnotherUsersDeposits() public {
        UsageEscrow.Claim memory c = UsageEscrow.Claim(operator, 11e6, 29);
        bytes memory sig = signature(user,c);
        vm.expectRevert("deposit exceeded"); rail.claim(user,c,sig);
        c.cumulativeOwed = 8e6; rail.claim(user,c,signature(user,c));
        c.operator = address(0x33); c.cumulativeOwed = 3e6;
        sig = signature(user,c);
        vm.expectRevert("deposit exceeded"); rail.claim(user,c,sig);
    }
    function testUserDomainPreventsCrossAccountReplay() public {
        UsageEscrow.Claim memory c = UsageEscrow.Claim(operator, 1e6, 29);
        bytes memory sig = signature(user,c);
        vm.expectRevert("broker signature"); rail.claim(other,c,sig);
    }
    function testEscapeWithoutBrokerAndOutstandingClaimWindow() public {
        vm.prank(user); rail.requestExit();
        vm.prank(user); vm.expectRevert("escape timeout"); rail.withdraw();
        UsageEscrow.Claim memory c = UsageEscrow.Claim(operator, 2e6, 29);
        rail.claim(user,c,signature(user,c));
        vm.warp(block.timestamp + rail.ESCAPE_DELAY());
        vm.prank(user); rail.withdraw();
        assertEq(usdc.balanceOf(user),8e6); assertEq(rail.balance(user),0);
        c.cumulativeOwed = 3e6;
        bytes memory sig = signature(user,c);
        vm.expectRevert("account exited"); rail.claim(user,c,sig);
        vm.startPrank(user); vm.expectRevert("amount or exiting"); rail.deposit(1); vm.stopPrank();
    }
}
