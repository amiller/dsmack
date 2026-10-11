// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {DemoV1} from "./DemoV1.sol";

/// The sample key faucet keeps its network address when all RAM key holders exit.
/// Recovery is an explicit administrative epoch change, never an implicit reset.
contract DemoV2 is DemoV1 {
    mapping(bytes32 => uint64) public keyEpochs;
    event KeyEpochStarted(bytes32 indexed scope, uint64 epoch);

    constructor(address admin) DemoV1(admin) {}

    function contextHash(Request calldata r) public view override returns (bytes32) {
        uint64 epoch = r.action == Action.Join || r.action == Action.Claim ? 0 : keyEpochs[r.scope];
        return keccak256(abi.encode("TEE_INTEROP_DEMO_V2", block.chainid, address(this), epoch, r));
    }

    /// Does not revoke membership or erase keys previously delivered to a peer.
    /// A fresh bootstrap is required before any further key release can succeed.
    function startKeyEpoch(bytes32 scope) external onlyOwner {
        if (scope != 0 && categories[scope].adapter == address(0)) revert InvalidRequest();
        keyEpochs[scope]++;
        delete sharedKeys[scope];
        emit KeyEpochStarted(scope, keyEpochs[scope]);
    }
}
