// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// An immutable, policy-specific adapter. Must authenticate expectedContext in
/// current evidence and return an authenticated subject, never an unsigned hint.
interface IAdmissionV1 {
    function verify(bytes32 expectedContext, bytes calldata proof) external returns (bytes32 subject);
}
