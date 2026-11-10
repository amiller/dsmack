// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// The page publisher announces the latest content-addressed page bundle.
contract PageBundleRegistry {
    address public immutable publisher;
    string public latestCID;
    event Published(string cid);

    constructor(address publisher_) {
        require(publisher_ != address(0), "publisher required");
        publisher = publisher_;
    }

    function publish(string calldata cid) external {
        require(msg.sender == publisher, "publisher only");
        // CIDv1 raw/sha2-256, lowercase base32: the build's deterministic tar.
        bytes memory value = bytes(cid);
        require(value.length == 59, "raw CID required");
        require(bytes7(value) == bytes7("bafkrei"), "raw CID required");
        for (uint256 i = 7; i < value.length; i++) {
            require((value[i] >= 0x61 && value[i] <= 0x7a) || (value[i] >= 0x32 && value[i] <= 0x37), "base32 required");
        }
        latestCID = cid;
        emit Published(cid);
    }
}
