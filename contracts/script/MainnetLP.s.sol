// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";

interface IERC20 { function approve(address, uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }
interface IPool { function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16, uint16, uint16, uint8, bool); }
interface IPositionManager {
    struct MintParams { address token0; address token1; uint24 fee; int24 tickLower; int24 tickUpper; uint256 amount0Desired;
        uint256 amount1Desired; uint256 amount0Min; uint256 amount1Min; address recipient; uint256 deadline; }
    function createAndInitializePoolIfNecessary(address token0, address token1, uint24 fee, uint160 sqrtPriceX96) external payable returns (address);
    function mint(MintParams calldata p) external payable returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);
}

/// A LAYC/USDC Uniswap v3 pool on Base at $1 and one USDC-only position from $0.80 to $1.00: a standing bid hosts can sell
/// earned LAYC into. LAYC and USDC both have 6 decimals, so tick 0 is $1. The position sits on the $1 side of the current
/// price, so it holds only USDC until LAYC trades below $1. The sender supplies LP_USDC (base units) and gets the position NFT.
contract MainnetLP is Script {
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    IPositionManager constant NPM = IPositionManager(0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1); // Uniswap v3, factory 0x3312…FdfD
    uint24 constant FEE = 3000; // 0.3%, tick spacing 60
    int24 constant EDGE = 2220; // 1.0001^-2220 = $0.8009
    uint160 constant ONE = 2 ** 96; // sqrtPriceX96 at price 1

    function run() external {
        require(block.chainid == 8453, "Base mainnet only");
        (address layc, uint256 usdc) = (vm.envAddress("LAYC"), vm.envUint("LP_USDC"));
        bool laycFirst = layc < USDC; // token0 is the lower address; price is token1 per token0
        (address t0, address t1) = laycFirst ? (layc, USDC) : (USDC, layc);
        // LAYC from $0.80 to $1: USDC per LAYC in [0.80, 1] if LAYC is token0, LAYC per USDC in [1, 1.25] if not.
        (int24 lo, int24 hi) = laycFirst ? (-EDGE, int24(0)) : (int24(0), EDGE);
        vm.startBroadcast();
        address pool = NPM.createAndInitializePoolIfNecessary(t0, t1, FEE, ONE);
        (uint160 price,,,,,,) = IPool(pool).slot0();
        require(price == ONE, "pool exists at another price");
        IERC20(USDC).approve(address(NPM), usdc);
        (uint256 id, uint128 liquidity, uint256 a0, uint256 a1) = NPM.mint(IPositionManager.MintParams(t0, t1, FEE, lo, hi,
            laycFirst ? 0 : usdc, laycFirst ? usdc : 0, laycFirst ? 0 : usdc * 999 / 1000, laycFirst ? usdc * 999 / 1000 : 0,
            msg.sender, block.timestamp + 600));
        vm.stopBroadcast();
        require((laycFirst ? a0 : a1) == 0, "position took LAYC");
        console2.log("pool", pool);
        console2.log("position", id, liquidity);
        console2.log("USDC in", laycFirst ? a1 : a0);
    }
}
