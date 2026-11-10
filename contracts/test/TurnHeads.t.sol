// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {TurnHeads} from "../src/TurnHeads.sol";

contract TurnHeadsTest is Test {
    TurnHeads h = new TurnHeads();
    uint256 constant KEY = 0xA6E47;

    function commit(uint256 key, uint256 turn, bytes32 stateIn, bytes32 stateOut) internal {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, h.digest(turn, stateIn, stateOut));
        h.commit(turn, stateIn, stateOut, v, r, s);
    }

    function testChainAdvancesOnce() public {
        commit(KEY, 0, 0, "s1");
        commit(KEY, 1, "s1", "s2");
        (uint256 turn, bytes32 state) = h.heads(vm.addr(KEY));
        assertEq(turn, 2);
        assertEq(state, "s2");
    }

    // A second turn from the same parent: the fork the head exists to refuse.
    function testForkFromSameParentIsStale() public {
        commit(KEY, 0, 0, "s1");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, h.digest(0, 0, "s1b"));
        vm.expectRevert("stale head");
        h.commit(0, 0, "s1b", v, r, s);
    }

    // The signature names the agent: another key's commit moves only its own head.
    function testOtherKeyDoesNotMoveTheAgent() public {
        commit(KEY, 0, 0, "s1");
        commit(KEY + 1, 0, 0, "x");
        (uint256 turn, bytes32 state) = h.heads(vm.addr(KEY));
        assertEq(turn, 1);
        assertEq(state, "s1");
    }

    // A commit signed by personal-agent/guest/agent_turn.py (secret bytes(range(32)), CHAIN_ID 31337, HEADS 0x7e4d),
    // so a digest or signature encoding that drifts from the guest's fails here.
    function testGuestCommitLands() public {
        TurnHeads g = TurnHeads(address(0x7e4D));
        vm.etch(address(g), address(h).code);
        vm.chainId(31337);
        g.commit(0, 0, bytes32(0x1111111111111111111111111111111111111111111111111111111111111111), 28,
            0xcb7d0450d11f1b3bff16a22ef7a5abc103d2c6200b95386fe3462a6a0277ee12,
            0x241228935f593e672f64e720f65e12ce80918fd639b656fcf73869850acfae99);
        (uint256 turn,) = g.heads(0x5178a63781F4DD05066739A03aA66d2Ae06bE490);
        assertEq(turn, 1);
    }
}
