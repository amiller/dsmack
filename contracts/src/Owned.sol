// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Two-step ownership: the owner names a pending owner, who takes over by calling acceptOwnership. Naming
/// address(0) cancels a pending transfer. Inheritors check `owner` themselves and validate the initial owner.
abstract contract Owned {
    address public owner;
    address public pendingOwner;
    event OwnershipTransferStarted(address indexed owner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previous, address indexed owner);

    constructor(address owner_) { owner = owner_; emit OwnershipTransferred(address(0), owner_); }
    function transferOwnership(address next) external {
        require(msg.sender == owner, "owner only");
        pendingOwner = next;
        emit OwnershipTransferStarted(owner, next);
    }
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "pending owner only");
        emit OwnershipTransferred(owner, msg.sender);
        (owner, pendingOwner) = (msg.sender, address(0));
    }
}
