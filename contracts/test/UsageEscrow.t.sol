// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import "forge-std/Test.sol";
import "../src/UsageEscrow.sol";

/// 6-decimal test token with the EIP-3009 subset x402 uses.
contract MockUSDC {
    uint8 public constant decimals = 6;
    bytes32 public constant TRANSFER_TYPEHASH = keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant CANCEL_TYPEHASH = keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("USDC"), keccak256("2"), block.chainid, address(this)));
    }
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address to, uint256 amount) external returns (bool) { allowance[msg.sender][to] = amount; return true; }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount; balanceOf[from] -= amount; balanceOf[to] += amount; return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true;
    }
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp > validAfter && block.timestamp < validBefore, "authorization time");
        _use(from, nonce, keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), v, r, s);
        balanceOf[from] -= value; balanceOf[to] += value;
    }
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _use(authorizer, nonce, keccak256(abi.encode(CANCEL_TYPEHASH, authorizer, nonce)), v, r, s);
    }
    function _use(address who, bytes32 nonce, bytes32 structHash, uint8 v, bytes32 r, bytes32 s) private {
        require(!authorizationState[who][nonce], "authorization used");
        require(ecrecover(keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)), v, r, s) == who, "invalid signature");
        authorizationState[who][nonce] = true;
    }
}

contract UsageEscrowTest is Test {
    UsageEscrow rail;
    MockUSDC usdc;
    address user = address(0x11);
    address other = address(0x12);
    address operator = address(0x22);
    uint256 brokerKey = 123;
    uint256 payerKey = 456;
    event BrokerRotated(address indexed previous, address indexed broker);
    bytes32 termsHash = keccak256("terms");
    uint256 deadline;
    function setUp() public {
        vm.warp(30 weeks); deadline = block.timestamp + 1 hours;
        usdc = new MockUSDC(); rail = new UsageEscrow(address(usdc), address(this));
        rail.registerBroker(vm.addr(brokerKey));
        fund(user, 10e6); fund(other, 100e6);
        vm.prank(user); rail.acceptTerms(termsHash, operator, 5e6);
        vm.prank(other); rail.acceptTerms(termsHash, operator, 100e6);
    }
    function fund(address who, uint256 amount) internal {
        usdc.mint(who, amount); vm.startPrank(who);
        usdc.approve(address(rail), amount); rail.deposit(amount); vm.stopPrank();
    }
    function sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest); return abi.encodePacked(r, s, v);
    }
    function claimSig(address who, UsageEscrow.Claim memory c) internal view returns (bytes memory) {
        return sign(brokerKey, rail.claimDigest(who, c));
    }
    function claimOf(uint256 owed) internal view returns (UsageEscrow.Claim memory) {
        return UsageEscrow.Claim(operator, termsHash, owed, 30);
    }
    function transferDigest(uint256 value, bytes32 nonce) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(usdc.TRANSFER_TYPEHASH(), vm.addr(payerKey), address(rail), value, 0, deadline, nonce));
        return keccak256(abi.encodePacked("\x19\x01", usdc.DOMAIN_SEPARATOR(), structHash));
    }
    function authorizationParts(uint256 value, bytes32 nonce) internal view returns (uint8, bytes32, bytes32) {
        return vm.sign(payerKey, transferDigest(value, nonce));
    }
    function authorization(uint256 value, bytes32 nonce) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = authorizationParts(value, nonce); return abi.encodePacked(r, s, v);
    }

    function testDepositAndCumulativeDebitClaim() public {
        assertEq(rail.balance(user), 10e6);
        UsageEscrow.Claim memory c = claimOf(2e6);
        rail.claim(user, c, claimSig(user, c));
        assertEq(usdc.balanceOf(operator), 2e6); assertEq(rail.balance(user), 8e6);
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("claim replay"); rail.claim(user, c, sig);
        c.cumulativeOwed = 3e6;
        rail.claim(user, c, claimSig(user, c));
        assertEq(usdc.balanceOf(operator), 3e6); assertEq(rail.claimed(user, termsHash), 3e6);
    }
    function testClaimExceedingTermsReverts() public {
        UsageEscrow.Claim memory c = claimOf(5e6 + 1);
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("terms cap"); rail.claim(user, c, sig);
        vm.expectRevert("terms cap"); rail.claim(user, c, new bytes(65));
        c.cumulativeOwed = 5e6; rail.claim(user, c, claimSig(user, c));
    }
    function testWrongOperatorReverts() public {
        UsageEscrow.Claim memory c = claimOf(1e6); c.operator = address(0x33);
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("terms operator"); rail.claim(user, c, sig);
    }
    function testUnacceptedTermsRevert() public {
        UsageEscrow.Claim memory c = claimOf(1e6); c.termsHash = keccak256("other terms");
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("terms not accepted"); rail.claim(user, c, sig);
    }
    function testTermsAcceptedOnce() public {
        vm.prank(user); vm.expectRevert("terms already accepted"); rail.acceptTerms(termsHash, address(0x33), 100e6);
    }
    function testRelayedAcceptTerms() public {
        address payer = vm.addr(payerKey); bytes32 h = keccak256("relayed");
        bytes memory sig = sign(payerKey, rail.termsDigest(payer, h, operator, 7e6));
        vm.expectRevert("terms signature"); rail.acceptTermsFor(payer, h, operator, 8e6, sig);
        vm.expectRevert("terms signature"); rail.acceptTermsFor(user, h, operator, 7e6, sig);
        rail.acceptTermsFor(payer, h, operator, 7e6, sig);
        (address op, uint256 cap) = rail.terms(payer, h);
        assertEq(op, operator); assertEq(cap, 7e6);
        vm.expectRevert("terms already accepted"); rail.acceptTermsFor(payer, h, operator, 7e6, sig);
    }
    function testOverClaimCannotUseAnotherUsersDeposits() public {
        bytes32 h = keccak256("big"); vm.prank(user); rail.acceptTerms(h, operator, 50e6);
        UsageEscrow.Claim memory c = UsageEscrow.Claim(operator, h, 11e6, 30);
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("deposit exceeded"); rail.claim(user, c, sig);
    }
    function testUserDomainPreventsCrossAccountReplay() public {
        UsageEscrow.Claim memory c = claimOf(1e6);
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("broker signature"); rail.claim(other, c, sig);
    }
    function testClaimPeriodMayBeCurrentWeekButNotFuture() public {
        UsageEscrow.Claim memory c = claimOf(1e6); c.period = 31;
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("claim period"); rail.claim(user, c, sig);
        c.period = 30; rail.claim(user, c, claimSig(user, c));
        c.period = 29; c.cumulativeOwed = 2e6; sig = claimSig(user, c);
        vm.expectRevert("claim period"); rail.claim(user, c, sig);
    }
    function testDepositForCreditsUser() public {
        address sponsor = address(0x44); address fresh = address(0x55);
        usdc.mint(sponsor, 3e6); vm.startPrank(sponsor); usdc.approve(address(rail), 3e6);
        rail.depositFor(fresh, 3e6); vm.stopPrank();
        assertEq(rail.balance(fresh), 3e6); assertEq(rail.balance(sponsor), 0); assertEq(usdc.balanceOf(sponsor), 0);
    }
    function testDepositWithAuthorizationCreditsOnce() public {
        address payer = vm.addr(payerKey); usdc.mint(payer, 2e6);
        bytes32 nonce = keccak256("n1"); bytes memory sig = authorization(2e6, nonce);
        rail.depositWithAuthorization(payer, 2e6, 0, deadline, nonce, sig);
        assertEq(rail.balance(payer), 2e6); assertEq(usdc.balanceOf(address(rail)), 112e6);
        vm.expectRevert("authorization used");
        rail.depositWithAuthorization(payer, 2e6, 0, deadline, nonce, sig);
    }
    function testFrontRunAuthorizationIsRefusedNotCredited() public {
        address payer = vm.addr(payerKey); usdc.mint(payer, 2e6);
        bytes32 nonce = keccak256("n2"); bytes memory sig = authorization(2e6, nonce);
        frontRun(payer, nonce);
        vm.expectRevert("authorization used");
        rail.depositWithAuthorization(payer, 2e6, 0, deadline, nonce, sig);
        assertEq(rail.balance(payer), 0);
    }
    function frontRun(address payer, bytes32 nonce) internal {
        (uint8 v, bytes32 r, bytes32 s) = authorizationParts(2e6, nonce);
        vm.prank(address(0x99));
        usdc.transferWithAuthorization(payer, address(rail), 2e6, 0, deadline, nonce, v, r, s);
    }
    function testCancelledAuthorizationRefused() public {
        address payer = vm.addr(payerKey); usdc.mint(payer, 2e6);
        bytes32 nonce = keccak256("n3"); bytes memory sig = authorization(2e6, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerKey, keccak256(abi.encodePacked("\x19\x01", usdc.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(usdc.CANCEL_TYPEHASH(), payer, nonce)))));
        usdc.cancelAuthorization(payer, nonce, v, r, s);
        vm.expectRevert("authorization used");
        rail.depositWithAuthorization(payer, 2e6, 0, deadline, nonce, sig);
    }
    function testWrongAuthorizationSignatureReverts() public {
        address payer = vm.addr(payerKey); usdc.mint(payer, 3e6);
        bytes32 nonce = keccak256("n4"); bytes memory sig = authorization(2e6, nonce);
        vm.expectRevert("invalid signature");
        rail.depositWithAuthorization(payer, 3e6, 0, deadline, nonce, sig);
        assertEq(rail.balance(payer), 0);
    }
    function testRotateBrokerRefusesOldSigner() public {
        UsageEscrow.Claim memory c = claimOf(1e6);
        bytes memory oldSig = claimSig(user, c);
        vm.prank(user); vm.expectRevert("broker rotation"); rail.rotateBroker(vm.addr(789));
        vm.expectEmit(); emit BrokerRotated(vm.addr(brokerKey), vm.addr(789));
        rail.rotateBroker(vm.addr(789));
        assertEq(rail.brokerSigner(), vm.addr(789));
        vm.expectRevert("broker signature"); rail.claim(user, c, oldSig);
        rail.claim(user, c, sign(789, rail.claimDigest(user, c)));
        assertEq(usdc.balanceOf(operator), 1e6);
        vm.expectRevert("broker admission"); rail.registerBroker(vm.addr(790));
    }
    function testEscapeWithoutBrokerAndOutstandingClaimWindow() public {
        vm.prank(user); rail.requestExit();
        vm.prank(user); vm.expectRevert("escape timeout"); rail.withdraw();
        UsageEscrow.Claim memory c = claimOf(2e6);
        rail.claim(user, c, claimSig(user, c));
        vm.warp(block.timestamp + rail.ESCAPE_DELAY());
        vm.prank(user); rail.withdraw();
        assertEq(usdc.balanceOf(user), 8e6); assertEq(rail.balance(user), 0);
        assertEq(usdc.balanceOf(address(rail)), 100e6);
        c.cumulativeOwed = 3e6;
        bytes memory sig = claimSig(user, c);
        vm.expectRevert("account exited"); rail.claim(user, c, sig);
        vm.startPrank(user); vm.expectRevert("amount or exiting"); rail.deposit(1); vm.stopPrank();
        vm.expectRevert("amount or exiting"); rail.depositFor(user, 1);
    }
}
