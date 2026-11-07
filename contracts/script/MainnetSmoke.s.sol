// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {GuestEscrow} from "../src/GuestEscrow.sol";

/// The issuance lane's LastResortBuyer (contracts/src/LastResortBuyer.sol on branch issuance), behind its proxy.
interface ILastResortBuyer {
    function advance() external;
    function commitBook(uint256 epoch, uint256 units, bytes calldata sig) external;
    function claim(bytes32 unitId, address operator, uint256 epoch, bytes32 workDigest, bytes calldata sig) external;
    function floor(uint256 epoch) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function BOOK_TYPEHASH() external view returns (bytes32);
    function UNIT_TYPEHASH() external view returns (bytes32);
}

interface IRouter {
    struct ExactInputSingleParams { address tokenIn; address tokenOut; uint24 fee; address recipient; uint256 amountIn;
        uint256 amountOutMinimum; uint160 sqrtPriceLimitX96; }
    function exactInputSingle(ExactInputSingleParams calldata p) external payable returns (uint256);
}
interface IERC20 { function approve(address, uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }

/// Anvil fork of Base mainnet only, after IssuanceLaunch, MainnetLaunch and MainnetLP, a day after LastResortBuyer deployed. GuestEscrow's verifier
/// has been replaced (anvil_setCode) by MockGuestAttest, since no real guest assertion exists for mainnet yet.
/// `open`: the host earns LAYC minted for one unit the minion bought from LastResortBuyer, sells it into the USDC bid, a buyer buys LAYC there and pays
/// the host through GuestEscrow (deposit, accept, claim, close). The caller advances the fork past CLAIM_GRACE; `settle`
/// withdraws the rest. Keys are anvil's dev keys.
contract MainnetSmoke is Script {
    uint256 constant RELAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // anvil 0
    uint256 constant BUYER = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a; // anvil 4
    uint256 constant OPERATOR = 0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba; // anvil 5
    uint256 constant MINION = 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97; // anvil 8
    uint256 constant GUEST = uint256(keccak256("layover mainnet smoke guest key"));
    IRouter constant ROUTER = IRouter(0x2626664c2603336E57B271c5C0b26F421741e481); // Uniswap SwapRouter02 on Base
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    bytes32 constant IMAGE = keccak256("smoke image");
    bytes32 constant MANIFEST = keccak256("smoke manifest");
    bytes32 constant CDHASH = keccak256("smoke runner cdhash");
    uint256 constant UNITS = 360;
    bytes32 constant TERMS = keccak256("layover-terms/1 buyer smoke");

    function open() external {
        require(block.chainid == 8453, "Base mainnet fork only");
        GuestEscrow esc = GuestEscrow(vm.envAddress("GUEST_ESCROW"));
        ILastResortBuyer lrb = ILastResortBuyer(vm.envAddress("LRB"));
        LayoverCredit layc = LayoverCredit(address(esc.token()));
        (address buyer, address op, bytes32 caller) = (vm.addr(BUYER), vm.addr(OPERATOR), sha256("agent"));

        vm.broadcast(vm.envAddress("OWNER"));
        esc.setWorkload(IMAGE, MANIFEST, caller, true);
        vm.startBroadcast(RELAYER);
        lrb.advance();
        uint256 e = layc.epoch();
        lrb.commitBook(e, UNITS, _sign(MINION, _lrbDigest(lrb, keccak256(abi.encode(lrb.BOOK_TYPEHASH(), e, UNITS)))));
        (bytes32 unit, bytes32 work) = (keccak256("smoke unit 1"), keccak256("smoke benchmark result"));
        lrb.claim(unit, op, e, work, _sign(MINION, _lrbDigest(lrb, keccak256(abi.encode(lrb.UNIT_TYPEHASH(), unit, op, e, work)))));
        _register(esc, op, caller);
        vm.stopBroadcast();
        uint256 minted = lrb.floor(e);
        require(minted == layc.reward(e) / UNITS && layc.balanceOf(op) == minted && layc.totalSupply() == minted, "host earned the floor");

        uint256 usdc0 = IERC20(USDC).balanceOf(op);
        vm.startBroadcast(OPERATOR);
        layc.approve(address(ROUTER), minted);
        ROUTER.exactInputSingle(IRouter.ExactInputSingleParams(address(layc), USDC, 3000, op, minted, minted * 79 / 100, 0));
        vm.stopBroadcast();
        console2.log("host sold LAYC units", minted);
        console2.log("  for USDC units", IERC20(USDC).balanceOf(op) - usdc0);

        vm.startBroadcast(BUYER);
        IERC20(USDC).approve(address(ROUTER), 5e6);
        ROUTER.exactInputSingle(IRouter.ExactInputSingleParams(USDC, address(layc), 3000, buyer, 5e6, 4e6, 0));
        vm.stopBroadcast();
        console2.log("buyer bought LAYC units for 5 USDC", layc.balanceOf(buyer));

        uint256 earned = layc.balanceOf(op);
        vm.startBroadcast(RELAYER);
        _depositWithAuthorization(layc, esc, buyer, 3e6, bytes32(uint256(1)));
        esc.acceptTermsFor(buyer, TERMS, op, 1e6, _sign(BUYER, esc.termsDigest(buyer, TERMS, op, 1e6)));
        esc.claim(buyer, TERMS, 4e5, _sign(GUEST, esc.claimDigest(buyer, op, TERMS, 4e5)));
        esc.closeTermsFor(buyer, TERMS, _sign(BUYER, esc.closeDigest(buyer, TERMS)));
        vm.stopBroadcast();
        require(layc.balanceOf(op) - earned == 4e5 && esc.balance(buyer) == 26e5 && esc.exposure(buyer) == 6e5, "buyer paid host");
        console2.log("open done: host earned one unit's floor in new LAYC and sold it; buyer bought LAYC, deposited 3, host claimed 0.4");
    }

    function settle() external {
        require(block.chainid == 8453, "Base mainnet fork only");
        GuestEscrow esc = GuestEscrow(vm.envAddress("GUEST_ESCROW"));
        LayoverCredit layc = LayoverCredit(address(esc.token()));
        address buyer = vm.addr(BUYER);
        bytes32[] memory expired = new bytes32[](1);
        expired[0] = TERMS;
        uint256 before = layc.balanceOf(buyer);
        vm.startBroadcast(RELAYER);
        esc.withdrawFor(buyer, buyer, 26e5, _sign(BUYER, esc.withdrawDigest(buyer, buyer, 26e5, esc.withdrawNonce(buyer))), expired);
        vm.stopBroadcast();
        require(layc.balanceOf(buyer) - before == 26e5 && esc.balance(buyer) == 0 && esc.exposure(buyer) == 0, "withdrawn");
        console2.log("settle done: buyer withdrew 2.6 LAYC after CLAIM_GRACE");
    }

    function _lrbDigest(ILastResortBuyer lrb, bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", lrb.DOMAIN_SEPARATOR(), structHash));
    }
    function _register(GuestEscrow esc, address op, bytes32 caller) internal {
        GuestEscrow.Attested memory a = GuestEscrow.Attested(IMAGE, MANIFEST, keccak256("run"), caller);
        GuestEscrow.Event[] memory ev = new GuestEscrow.Event[](1);
        ev[0] = GuestEscrow.Event("system-ready", "");
        bytes32 ctx = sha256(abi.encodePacked("dsmack.appattest.guest-attest/1", a.image, a.manifest, a.run, esc.eventHead(ev), a.caller,
            abi.encode(vm.addr(GUEST), op)));
        esc.registerGuestKey(vm.addr(GUEST), op, a, ev, abi.encode(ctx, CDHASH));
    }
    function _depositWithAuthorization(LayoverCredit layc, GuestEscrow esc, address from, uint256 value, bytes32 nonce) internal {
        bytes32 s = keccak256(abi.encode(layc.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), from, address(esc), value, 0, type(uint256).max, nonce));
        esc.depositWithAuthorization(from, value, 0, type(uint256).max, nonce,
            _sign(BUYER, keccak256(abi.encodePacked("\x19\x01", layc.DOMAIN_SEPARATOR(), s))));
    }
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
