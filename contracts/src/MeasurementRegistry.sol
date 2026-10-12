// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Measurement} from "./Measurement.sol";

/// Admits code measurements (Measurement.sol), not CDHashes. The owner opens a window
/// [activateAt, expireAt) in block numbers per measurement; windows of several measurements may
/// overlap so the group key moves across versions without an epoch bump. Anyone registers a
/// signed copy (any Apple team) whose measurement has an open or future window; its CDHash then
/// resolves to the RP, team and bundle hashes sealed in its entitlements while the window is open.
/// Keeps CDRegistry's reads (rpIdHash, teamIdHash, bundleIdHash) for the adapter and Upgrade.swift.
contract MeasurementRegistry {
    struct Window { uint64 from; uint64 until; }
    address public immutable owner = msg.sender;
    mapping(bytes32 => Window) public windows;
    mapping(bytes32 => bytes32) public measurementOf;
    mapping(bytes32 => bytes32) rp;
    mapping(bytes32 => bytes32) team;
    mapping(bytes32 => bytes32) bundle;
    event Admitted(bytes32 indexed m, uint64 activateAt, uint64 expireAt);
    event Registered(bytes32 indexed cdhash, bytes32 indexed m);
    /// Opens or replaces m's window. Shortening an old window's expiry ends its overlap.
    function admit(bytes32 m, uint64 activateAt, uint64 expireAt) external {
        require(msg.sender == owner, "owner");
        require(activateAt < expireAt, "window");
        windows[m] = Window(activateAt, expireAt);
        emit Admitted(m, activateAt, expireAt);
    }
    function revoke(bytes32 m) external {
        require(msg.sender == owner, "owner");
        delete windows[m];
        emit Admitted(m, 0, 0);
    }
    function isAdmitted(bytes32 m, uint256 blockNumber) public view returns (bool) {
        Window memory w = windows[m];
        return w.from <= blockNumber && blockNumber < w.until;
    }
    function measure(bytes calldata cd, bytes calldata page0, bytes calldata ent, uint256 L, uint256 S) external pure returns (bytes32) {
        return Measurement.measure(cd, page0, ent, L, S);
    }
    function register(bytes calldata cd, bytes calldata page0, bytes calldata ent, uint256 L, uint256 S) external returns (bytes32 h) {
        bytes32 m = Measurement.measure(cd, page0, ent, L, S);
        require(windows[m].until > block.number, "measurement not admitted");
        h = sha256(cd);
        (bytes32 app, bytes32 t, bytes32 b) = Measurement.identity(ent);
        require(app != 0, "application-identifier");
        (measurementOf[h], rp[h], team[h], bundle[h]) = (m, app, t, b);
        emit Registered(h, m);
    }
    /// The adapter's check: zero unless h is registered and its measurement is admitted now.
    function rpIdHash(bytes32 h) public view returns (bytes32) { return isAdmitted(measurementOf[h], block.number) ? rp[h] : bytes32(0); }
    function teamIdHash(bytes32 h) external view returns (bytes32) { return rpIdHash(h) != 0 ? team[h] : bytes32(0); }
    function bundleIdHash(bytes32 h) external view returns (bytes32) { return rpIdHash(h) != 0 ? bundle[h] : bytes32(0); }
}
