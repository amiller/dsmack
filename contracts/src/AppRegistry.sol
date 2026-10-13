// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// The dsmack-sdk app table (planning: dsmack-sdk design §3). An app is a stable bytes32 id with an
/// admin and a key scope; its admin opens block windows [from, until) for the compose hashes allowed
/// to derive its keys, as MeasurementRegistry opens windows for node measurements. The owner creates
/// apps and names their admins. A node releases an app root only if isAllowed at the block it checked.
contract AppRegistry {
    struct App { address admin; bytes32 scope; }
    struct Window { uint64 from; uint64 until; }
    address public immutable owner = msg.sender;
    mapping(bytes32 => App) public apps;
    mapping(bytes32 => mapping(bytes32 => Window)) public composes;
    event AppCreated(bytes32 indexed appId, bytes32 scope);
    event AdminSet(bytes32 indexed appId, address admin);
    event ComposeAdmitted(bytes32 indexed appId, bytes32 indexed composeHash, uint64 from, uint64 until);

    function createApp(bytes32 appId, address admin, bytes32 scope) external {
        require(msg.sender == owner, "owner");
        require(appId != 0 && apps[appId].admin == address(0), "app id");
        require(admin != address(0), "admin");
        apps[appId] = App(admin, scope);
        emit AppCreated(appId, scope);
        emit AdminSet(appId, admin);
    }
    function setAdmin(bytes32 appId, address admin) external {
        require(msg.sender == owner, "owner");
        require(apps[appId].admin != address(0) && admin != address(0), "admin");
        apps[appId].admin = admin;
        emit AdminSet(appId, admin);
    }
    /// Opens or replaces a compose window. Shortening an old window's until ends an upgrade overlap.
    function admit(bytes32 appId, bytes32 composeHash, uint64 from, uint64 until) external {
        require(msg.sender == apps[appId].admin && msg.sender != address(0), "app admin");
        require(from < until, "window");
        composes[appId][composeHash] = Window(from, until);
        emit ComposeAdmitted(appId, composeHash, from, until);
    }
    function revoke(bytes32 appId, bytes32 composeHash) external {
        require(msg.sender == apps[appId].admin && msg.sender != address(0), "app admin");
        delete composes[appId][composeHash];
        emit ComposeAdmitted(appId, composeHash, 0, 0);
    }
    function isAllowed(bytes32 appId, bytes32 composeHash, uint256 blockNumber) external view returns (bool) {
        Window memory w = composes[appId][composeHash];
        return apps[appId].admin != address(0) && w.from <= blockNumber && blockNumber < w.until;
    }
}
