// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Agent turn heads. An agent is the address of a key that only its attested turns derive, from the task
/// secret the secret-release policy gives them. A turn signs (turn, stateIn, stateOut) and anyone submits it;
/// the head moves from (turn, stateIn) to (turn + 1, stateOut) once. A new agent starts at (0, 0).
contract TurnHeads {
    struct Head { uint256 turn; bytes32 state; }
    mapping(address => Head) public heads;
    event Committed(address indexed agent, uint256 turn, bytes32 stateIn, bytes32 stateOut);

    function digest(uint256 turn, bytes32 stateIn, bytes32 stateOut) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), turn, stateIn, stateOut));
    }

    function commit(uint256 turn, bytes32 stateIn, bytes32 stateOut, uint8 v, bytes32 r, bytes32 s) external {
        address agent = ecrecover(digest(turn, stateIn, stateOut), v, r, s);
        require(agent != address(0), "signature");
        require(heads[agent].turn == turn && heads[agent].state == stateIn, "stale head");
        heads[agent] = Head(turn + 1, stateOut);
        emit Committed(agent, turn, stateIn, stateOut);
    }
}
