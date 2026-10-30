// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract SyncHeads {
    address public immutable writer;
    struct Head { uint256 counter; bytes32 digest; }
    mapping(address => Head) public heads;
    event Updated(address indexed wallet, uint256 counter, bytes32 digest);
    constructor(address writer_) { writer = writer_; }
    function commit(address wallet, uint256 previous, bytes32 digest) external {
        require(msg.sender == writer, "writer");
        require(heads[wallet].counter == previous, "head changed");
        heads[wallet] = Head(previous + 1, digest);
        emit Updated(wallet, previous + 1, digest);
    }
}
