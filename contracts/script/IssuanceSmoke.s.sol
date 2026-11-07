// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {LastResortBuyer} from "../src/LastResortBuyer.sol";

/// Anvil fork of Base mainnet only, after IssuanceLaunch and one day of fork time. MINION is anvil key 7. `pay` advances the
/// epoch, commits a book of 8 units (floor reward/8) and pays two minion-signed units to one operator. `refusals` sends
/// nothing: it calls against the fork state and requires each refusal with its reason. `newImpl` deploys a second
/// implementation for the controller's upgrade.
contract IssuanceSmoke is Script {
    uint256 constant MINION = 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356; // anvil 7
    uint256 constant RELAYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // anvil 0
    address constant OPERATOR = 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc; // anvil 5
    bytes32 constant WORK = keccak256("fork rehearsal work");

    function lrb() internal view returns (LastResortBuyer) { return LastResortBuyer(vm.envAddress("LRB")); }
    function sign(LastResortBuyer b, uint256 key, bytes32 structHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, keccak256(abi.encodePacked("\x19\x01", b.DOMAIN_SEPARATOR(), structHash)));
        return abi.encodePacked(r, s, v);
    }
    function unit(LastResortBuyer b, uint256 key, bytes32 id, address op, uint256 e) internal view returns (bytes memory) {
        return sign(b, key, keccak256(abi.encode(b.UNIT_TYPEHASH(), id, op, e, WORK)));
    }

    function pay() external {
        require(block.chainid == 8453, "Base mainnet fork only");
        LastResortBuyer b = lrb();
        LayoverCredit layc = b.token();
        vm.startBroadcast(RELAYER);
        b.advance();
        uint256 e = layc.epoch();
        b.commitBook(e, 8, sign(b, MINION, keccak256(abi.encode(b.BOOK_TYPEHASH(), e, 8))));
        b.claim("unit-1", OPERATOR, e, WORK, unit(b, MINION, "unit-1", OPERATOR, e));
        b.claim("unit-2", OPERATOR, e, WORK, unit(b, MINION, "unit-2", OPERATOR, e));
        vm.stopBroadcast();
        require(layc.balanceOf(OPERATOR) == 2 * layc.reward(e) / 8 && layc.totalSupply() == 2 * layc.reward(e) / 8, "paid");
        console2.log("epoch", e, "floor", b.floor(e));
        console2.log("operator balance", layc.balanceOf(OPERATOR), "totalSupply", layc.totalSupply());
    }

    function refusals() external {
        LastResortBuyer b = lrb();
        uint256 e = b.token().epoch();
        refused(abi.encodeCall(b.claim, ("unit-1", OPERATOR, e, WORK, unit(b, MINION, "unit-1", OPERATOR, e))), "unit paid", "duplicate unit-1");
        refused(abi.encodeCall(b.claim, ("unit-3", OPERATOR, e, WORK, unit(b, MINION, "unit-3", OPERATOR, e))), "operator cap", "third unit to one operator");
        refused(abi.encodeCall(b.claim, ("unit-4", address(0x44), e, WORK, unit(b, RELAYER, "unit-4", address(0x44), e))), "not minion", "unit signed by a non-minion key");
        refused(abi.encodeCall(b.advance, ()), "period not over", "second advance within 24h");
        refused(abi.encodeCall(b.setMinion, (address(0x44))), "controller only", "setMinion by a non-controller");
        (bool ok, bytes memory r) = address(b.token()).call(abi.encodeCall(LayoverCredit.mint, (b.controller(), 1)));
        require(!ok && keccak256(r) == keccak256(abi.encodeWithSignature("Error(string)", "owner only")), "controller mint");
        console2.log("refused: LAYC.mint from the controller (owner only)");
    }
    function refused(bytes memory data, string memory reason, string memory what) internal {
        vm.prank(vm.addr(RELAYER));
        (bool ok, bytes memory r) = address(lrb()).call(data);
        require(!ok && keccak256(r) == keccak256(abi.encodeWithSignature("Error(string)", reason)), what);
        console2.log(string.concat("refused: ", what, " (", reason, ")"));
    }

    function newImpl() external {
        vm.broadcast(RELAYER);
        LastResortBuyer impl = new LastResortBuyer(lrb().token());
        console2.log("NEW_IMPL", address(impl));
    }
}
