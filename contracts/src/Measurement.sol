// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {StrictDER} from "./StrictDER.sol";

/// Signer-independent code measurement M of a signed arm64 Mach-O (open-admission design §2;
/// same definition as scripts/release/measure.py and node/shared/Measure.swift).
/// Inputs: cd = CodeDirectory, page0 = first 16 KiB, ent = DER entitlements body (slot -7),
/// L, S = page-0 offsets of the __LINKEDIT LC_SEGMENT_64 and LC_CODE_SIGNATURE.
/// Bound: version, flags, page/hash parameters, execSeg, runtime, code slots, masked page 0,
/// and every entitlement pair except the identity values. Dropped: identifier, team ID,
/// slots -1, -2, -3, -5, identity entitlement values and the CMS signature.
library Measurement {
    bytes32 constant APP = keccak256("application-identifier");
    bytes32 constant APP2 = keccak256("com.apple.application-identifier");
    bytes32 constant TEAM = keccak256("com.apple.developer.team-identifier");
    bytes32 constant KEYCHAIN = keccak256("keychain-access-groups");
    function be32(bytes calldata b, uint256 o) private pure returns (uint256) { return uint32(bytes4(b[o:o + 4])); }
    function le32(bytes calldata b, uint256 o) private pure returns (uint256) {
        return uint8(b[o]) | uint256(uint8(b[o + 1])) << 8 | uint256(uint8(b[o + 2])) << 16 | uint256(uint8(b[o + 3])) << 24;
    }
    function measure(bytes calldata cd, bytes calldata page0, bytes memory ent, uint256 L, uint256 S) internal pure returns (bytes32 m) {
        require(cd.length >= 0x60 && be32(cd, 0) == 0xfade0c02 && be32(cd, 4) == cd.length && be32(cd, 8) == 0x20500, "blob");
        require(cd[0x24] == 0x20 && cd[0x25] == 0x02 && cd[0x27] == 0x0e && be32(cd, 0x2c) == 0 && be32(cd, 0x18) == 7, "layout");
        uint256 off = be32(cd, 0x10);
        uint256 end = off + 32 * be32(cd, 0x1c);
        require(off >= 224 && end <= cd.length && end > off, "bounds");
        require(bytes32(cd[off - 128:off - 96]) == 0 && bytes32(cd[off - 192:off - 160]) == 0, "slots -4/-6");
        require(page0.length == 16384 && sha256(page0) == bytes32(cd[off:off + 32]), "page0 hash");
        require(sha256(abi.encodePacked(uint32(0xfade7172), uint32(ent.length + 8), ent)) == bytes32(cd[off - 224:off - 192]), "entitlements slot");
        require(L <= 16384 - 56 && S <= 16384 - 16 && le32(page0, L) == 0x19 && bytes16(page0[L + 8:L + 24]) == bytes16("__LINKEDIT")
            && le32(page0, S) == 0x1d, "load commands");
        bytes memory masked = page0;
        assembly ("memory-safe") {
            let d := add(masked, 0x20)
            mstore(add(d, add(L, 32)), and(mload(add(d, add(L, 32))), not(shl(192, not(0)))))
            mstore(add(d, add(L, 48)), and(mload(add(d, add(L, 48))), not(shl(192, not(0)))))
            mstore(add(d, add(S, 12)), and(mload(add(d, add(S, 12))), not(shl(224, not(0)))))
        }
        m = sha256(bytes.concat("dsmack.measure.v1", cd[8:16], cd[0x1c:0x30], cd[0x34:0x60], bytes4(uint32(L)), bytes4(uint32(S)),
            sha256(masked), cd[off + 32:end], shape(ent)));
    }
    function dict(bytes memory der) private pure returns (StrictDER.Node memory d) {
        StrictDER.Node memory outer = StrictDER.expect(der, 0, der.length, 0x70);
        StrictDER.Node memory version = StrictDER.expect(der, outer.body, outer.end, 0x02);
        require(outer.end == der.length && version.end == version.body + 1 && der[version.body] == 0x01, "entitlements");
        d = StrictDER.expect(der, version.end, outer.end, 0xb0);
        require(d.end == outer.end, "entitlements");
    }
    /// Each pair as 0x01 || DER(pair), identity keys as 0x00 || DER(key), in blob order.
    function shape(bytes memory der) private pure returns (bytes memory e) {
        StrictDER.Node memory d = dict(der);
        for (uint256 p = d.body; p < d.end; ) {
            StrictDER.Node memory pair = StrictDER.expect(der, p, d.end, 0x30);
            StrictDER.Node memory key = StrictDER.expect(der, pair.body, pair.end, 0x0c);
            require(StrictDER.node(der, key.end, pair.end).end == pair.end, "entitlements");
            bytes32 k = keccak256(StrictDER.contents(der, key));
            e = k == APP || k == APP2 || k == TEAM || k == KEYCHAIN
                ? bytes.concat(e, hex"00", StrictDER.encoded(der, key))
                : bytes.concat(e, hex"01", StrictDER.encoded(der, pair));
            p = pair.end;
        }
    }
    /// sha256 of the application-identifier, team-identifier and bundle suffix (after the App ID prefix);
    /// zero when absent. Same rules as CDRegistry.entitlementIdentity. Call after measure (shape already checked).
    function identity(bytes memory der) internal pure returns (bytes32 app, bytes32 team, bytes32 bundle) {
        StrictDER.Node memory d = dict(der);
        for (uint256 p = d.body; p < d.end; ) {
            StrictDER.Node memory pair = StrictDER.expect(der, p, d.end, 0x30);
            StrictDER.Node memory key = StrictDER.expect(der, pair.body, pair.end, 0x0c);
            StrictDER.Node memory value = StrictDER.node(der, key.end, pair.end);
            bytes32 k = keccak256(StrictDER.contents(der, key));
            if (k == APP || k == APP2) {
                require(app == 0 && value.tag == 0x0c, "application-identifier");
                bytes memory id = StrictDER.contents(der, value);
                app = sha256(id);
                for (uint256 i = 1; i + 1 < id.length; i++) if (id[i] == ".") {
                    bundle = sha256(StrictDER.slice(id, i + 1, id.length));
                    break;
                }
            } else if (k == TEAM) {
                require(team == 0 && value.tag == 0x0c && value.end - value.body == 10, "team-identifier");
                for (uint256 i = value.body; i < value.end; i++) {
                    bytes1 ch = der[i];
                    require((ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9"), "team-identifier");
                }
                team = sha256(StrictDER.contents(der, value));
            }
            p = pair.end;
        }
    }
}
