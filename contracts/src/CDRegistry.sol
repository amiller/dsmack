// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {StrictDER} from "attest/StrictDER.sol";

/// Admits re-signed copies of one approved Mach-O, by any signer. Pinned (behavior):
/// - code slots 1..n and codeLimit;
/// - page 0 after masking the three signer-dependent fields (__LINKEDIT vmsize, filesize;
///   LC_CODE_SIGNATURE datasize);
/// - CodeDirectory header fields that change execution: version, flags (hardened runtime,
///   ad hoc), hash/page parameters, execSeg base/limit/flags, runtime version;
/// - the DER entitlements (slot -7): same keys in the same order and byte-equal values, except
///   the identity keys (application-identifier, team-identifier, keychain-access-groups),
///   whose values AMFI checks against the signer's provisioning profile at launch.
/// Free (signer identity, no effect on the executable's code or privileges): CD identifier,
/// team ID, slots -1 (Info.plist), -2 (requirements), -3 (resources), -5 (XML entitlements),
/// and the CMS signature.
/// Info.plist is not pinned: the probe/node apps read no Info.plist keys, and hardened runtime
/// (pinned) blocks DYLD_* injection through LSEnvironment. Residual: a re-signer can change
/// non-code bundle metadata (e.g. ATS exceptions, LSEnvironment for non-DYLD variables).
/// Each admitted CDHash records rpIdHash = sha256(application-identifier), the App Attest RP ID.
/// The owner sets the current build; rpIdHash resolves only CDHashes registered under it.
/// Copies of any build ever approved stay registrable, and buildOf/rpOf resolve them, so a
/// consumer can pin a build (Canary entries) independently of setBuild.
contract CDRegistry {
    struct Build {
        bytes32 rest;
        bytes32 maskedPage0;
        bytes32 header;
        bytes32 entitlements;
        uint256 codeLimit;
        uint256 linkeditCmd;
        uint256 codeSigCmd;
    }
    address public immutable owner = msg.sender;
    mapping(bytes32 => bool) public approved;
    bytes32 public buildId;
    mapping(bytes32 => bytes32) public rpOf;
    mapping(bytes32 => bytes32) public buildOf;
    mapping(bytes32 => bytes32) team;
    mapping(bytes32 => bytes32) bundle;
    function be32(bytes calldata b, uint256 o) internal pure returns (uint256) { return uint32(bytes4(b[o:o + 4])); }
    function le32(bytes calldata b, uint256 o) internal pure returns (uint256 x) {
        x = be32(b, o);
        x = (x >> 24) | (x >> 8 & 0xff00) | (x << 8 & 0xff0000) | (x << 24 & 0xff000000);
    }
    /// Page-0 offsets of the __LINKEDIT LC_SEGMENT_64 and LC_CODE_SIGNATURE of a thin arm64 Mach-O.
    function loadCommands(bytes calldata page0) public pure returns (uint256 linkedit, uint256 codeSig) {
        require(le32(page0, 0) == 0xfeedfacf && le32(page0, 4) == 0x0100000c, "thin arm64");
        uint256 end = 32 + le32(page0, 20);
        require(end <= page0.length, "load commands");
        uint256 off = 32;
        for (uint256 n = le32(page0, 16); n > 0; n--) {
            (uint256 cmd, uint256 sz) = (le32(page0, off), le32(page0, off + 4));
            require(sz >= 8 && off + sz <= end, "load commands");
            if (cmd == 0x19 && bytes16(page0[off + 8:off + 24]) == "__LINKEDIT") {
                require(linkedit == 0 && sz == 72, "__LINKEDIT");
                linkedit = off;
            }
            if (cmd == 0x1d) {
                require(codeSig == 0 && sz == 16, "LC_CODE_SIGNATURE");
                codeSig = off;
            }
            off += sz;
        }
        require(linkedit != 0, "__LINKEDIT");
        require(codeSig != 0, "LC_CODE_SIGNATURE");
    }
    function maskedHash(bytes memory p, uint256 linkedit, uint256 codeSig) public pure returns (bytes32 h) {
        assembly {
            let d := add(p, 0x20)
            mstore(add(d, add(linkedit, 32)), and(mload(add(d, add(linkedit, 32))), not(shl(192, not(0)))))
            mstore(add(d, add(linkedit, 48)), and(mload(add(d, add(linkedit, 48))), not(shl(192, not(0)))))
            mstore(add(d, add(codeSig, 12)), and(mload(add(d, add(codeSig, 12))), not(shl(224, not(0)))))
            h := keccak256(d, mload(p))
        }
    }
    /// Hash of the entitlement shape (identity values blanked) and sha256(application-identifier).
    function entitlements(bytes memory der) public pure returns (bytes32 shape, bytes32 app) {
        (shape, app,,) = entitlementIdentity(der);
    }
    /// Identity metadata is sealed by the CDHash, but is not proof of execution.
    /// Consumers must also verify a live Apple assertion for that CDHash/RP pair.
    function entitlementIdentity(bytes memory der) public pure returns (bytes32 shape, bytes32 app, bytes32 teamHash, bytes32 bundleHash) {
        StrictDER.Node memory outer = StrictDER.expect(der, 0, der.length, 0x70);
        StrictDER.Node memory version = StrictDER.expect(der, outer.body, outer.end, 0x02);
        require(outer.end == der.length && version.end == version.body + 1 && der[version.body] == 0x01, "entitlements");
        StrictDER.Node memory dict = StrictDER.expect(der, version.end, outer.end, 0xb0);
        require(dict.end == outer.end, "entitlements");
        for (uint256 p = dict.body; p < dict.end;) {
            StrictDER.Node memory pair = StrictDER.expect(der, p, dict.end, 0x30);
            StrictDER.Node memory key = StrictDER.expect(der, pair.body, pair.end, 0x0c);
            StrictDER.Node memory value = StrictDER.node(der, key.end, pair.end);
            require(value.end == pair.end, "entitlements");
            bytes32 k = keccak256(StrictDER.contents(der, key));
            if (k == keccak256("application-identifier") || k == keccak256("com.apple.application-identifier")) {
                require(app == 0 && value.tag == 0x0c, "application-identifier");
                bytes memory appIdentifier = StrictDER.contents(der, value);
                app = sha256(appIdentifier);
                // App ID prefix may differ from the team ID on legacy accounts.
                // Bind the bundle suffix without treating the prefix as a team.
                for (uint256 i; i < appIdentifier.length; i++) {
                    if (appIdentifier[i] == "." && i > 0 && i + 1 < appIdentifier.length) {
                        bytes memory suffix = new bytes(appIdentifier.length - i - 1);
                        for (uint256 j; j < suffix.length; j++) suffix[j] = appIdentifier[i + 1 + j];
                        bundleHash = sha256(suffix);
                        break;
                    }
                }
                shape = keccak256(abi.encode(shape, k));
            } else if (k == keccak256("com.apple.developer.team-identifier")) {
                require(teamHash == 0 && value.tag == 0x0c, "team-identifier");
                bytes memory identifier = StrictDER.contents(der, value);
                require(identifier.length == 10, "team-identifier");
                for (uint256 i; i < identifier.length; i++) {
                    bytes1 ch = identifier[i];
                    require((ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9"), "team-identifier");
                }
                teamHash = sha256(identifier);
                shape = keccak256(abi.encode(shape, k));
            } else if (k == keccak256("keychain-access-groups")) {
                shape = keccak256(abi.encode(shape, k));
            } else shape = keccak256(abi.encode(shape, keccak256(StrictDER.encoded(der, pair))));
            p = pair.end;
        }
        require(app != 0, "application-identifier");
    }
    function header(bytes calldata cd) internal pure returns (bytes32) {
        return keccak256(bytes.concat(cd[8:16], cd[0x24:0x30], cd[0x34:be32(cd, 8) >= 0x20500 ? 0x60 : 0x58]));
    }
    function measure(bytes calldata cd, bytes calldata page0, bytes calldata ent) public pure returns (Build memory b, bytes32 app) {
        require(be32(cd, 0) == 0xfade0c02 && be32(cd, 4) == cd.length, "blob");
        require(cd[0x24] == 0x20 && cd[0x25] == 0x02 && cd[0x27] == 0x0e && page0.length == 16384, "sha256/16KiB");
        uint256 off = be32(cd, 0x10);
        uint256 end = off + 32 * be32(cd, 0x1c);
        require(end <= cd.length && sha256(page0) == bytes32(cd[off:off + 32]), "page0 hash");
        require(be32(cd, 0x18) >= 7 && sha256(abi.encodePacked(uint32(0xfade7172), uint32(ent.length + 8), ent)) == bytes32(cd[off - 7 * 32:off - 6 * 32]), "entitlements slot");
        (b.entitlements, app) = entitlements(ent);
        b.rest = keccak256(cd[off + 32:end]);
        (b.linkeditCmd, b.codeSigCmd) = loadCommands(page0);
        b.maskedPage0 = maskedHash(page0, b.linkeditCmd, b.codeSigCmd);
        b.header = header(cd);
        b.codeLimit = be32(cd, 0x20);
    }
    function setBuild(bytes calldata cd, bytes calldata page0, bytes calldata ent) external {
        require(msg.sender == owner, "owner");
        (Build memory b,) = measure(cd, page0, ent);
        buildId = keccak256(abi.encode(b));
        approved[buildId] = true;
    }
    /// A copy whose code, masked page 0, CodeDirectory header and entitlement shape match an approved build.
    function registerBuild(bytes calldata cd, bytes calldata page0, bytes calldata ent) external returns (bytes32 h) {
        (Build memory b, bytes32 app) = measure(cd, page0, ent);
        bytes32 id = keccak256(abi.encode(b));
        require(approved[id], "not an approved build");
        h = sha256(cd);
        rpOf[h] = app;
        (,,team[h],bundle[h]) = entitlementIdentity(ent);
        buildOf[h] = id;
    }
    function rpIdHash(bytes32 h) public view returns (bytes32) { return buildOf[h] == buildId ? rpOf[h] : bytes32(0); }
    /// Zero when absent or no longer admitted under the current approved build.
    function teamIdHash(bytes32 h) public view returns (bytes32) { return rpIdHash(h) != 0 ? team[h] : bytes32(0); }
    function bundleIdHash(bytes32 h) public view returns (bytes32) { return rpIdHash(h) != 0 ? bundle[h] : bytes32(0); }
    function isAdmitted(bytes32 h) external view returns (bool) { return rpIdHash(h) != 0; }
}
