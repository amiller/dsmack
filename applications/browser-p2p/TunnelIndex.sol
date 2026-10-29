// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TunnelIndex {
    address public immutable owner;
    constructor(address publisher) { owner = publisher; }
    string public entries;
    event Published(string entries);
    function publish(string calldata value) external {
        require(msg.sender == owner, "owner");
        entries = value;
        emit Published(value);
    }
}
