// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {IAttestVerifier, ICDRegistry} from "./Canary.sol";

/// Non-transferable ERC721: one badge per App Attest key, minted to the address named by a guest
/// Attest from the pinned badge workload, on a runner copy registered in CDRegistry under `build`.
/// The workload measures its CPU's class from inside the guest and binds it with
/// report_data = reportData(to, chip). Token id is the key id. The verifier is an AppleAttestAnyBuildV1
/// deployed with registry = this contract.
contract Badge {
    struct Attested { bytes32 image; bytes32 manifest; bytes32 run; bytes32 head; bytes32 caller; bytes reportData; }
    struct Info { bytes32 chip; bytes32 cdhash; uint64 claimedAt; }
    bytes constant ATTEST_DOMAIN = "dsmack.appattest.guest-attest/1";
    bytes constant BADGE_DOMAIN = "dsmack.badge.claim/2";
    string public constant name = "dsmack Mac badge";
    string public constant symbol = "DSMACK";
    IAttestVerifier public immutable attest;
    ICDRegistry public immutable cds;
    bytes32 public immutable build;
    bytes32 public immutable manifest;
    mapping(uint256 => address) owners;
    mapping(uint256 => Info) public info;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    constructor(IAttestVerifier attest_, bytes32 build_, bytes32 manifest_) {
        require(build_ != 0 && manifest_ != 0, "pins");
        (attest, cds, build, manifest) = (attest_, attest_.cds(), build_, manifest_);
    }

    function reportData(address to, bytes32 chip) public view returns (bytes memory) {
        return abi.encodePacked(sha256(abi.encodePacked(BADGE_DOMAIN, block.chainid, address(this), to, chip)), bytes32(0));
    }

    function claim(address to, bytes32 chip, Attested calldata a, bytes calldata proof) external returns (uint256 id) {
        require(a.manifest == manifest, "manifest");
        require(to != address(0) && keccak256(a.reportData) == keccak256(reportData(to, chip)), "report_data");
        bytes32 kid = attest.verify(sha256(abi.encodePacked(ATTEST_DOMAIN, a.image, a.manifest, a.run, a.head, a.caller, a.reportData)), proof);
        (, bytes32 cdhash,,,) = attest.assertionEvidence(kid);
        require(cds.buildOf(cdhash) == build, "build");
        id = uint256(kid);
        require(owners[id] == address(0), "claimed");
        owners[id] = to;
        info[id] = Info(chip, cdhash, uint64(block.timestamp));
        balanceOf[to]++;
        emit Transfer(address(0), to, id);
    }

    function ownerOf(uint256 id) public view returns (address o) {
        require((o = owners[id]) != address(0), "no badge");
    }

    function tokenURI(uint256 id) external view returns (string memory) {
        ownerOf(id);
        Info memory i = info[id];
        string memory chip = label(i.chip);
        bytes memory json = abi.encodePacked('{"name":"dsmack Mac badge: Apple ', chip, '","description":"Claimed by an attested dsmack guest on a Mac. The guest measured its CPU class; App Attest and the runner build are checked on chain.","attributes":[{"trait_type":"CPU class","value":"', chip,
            '"},{"trait_type":"Runner","value":"0x', hexs(i.cdhash, 4), '"}],"image":"data:image/svg+xml;base64,', b64(svg(id, chip, i)), '"}');
        return string(abi.encodePacked("data:application/json;base64,", b64(json)));
    }

    function svg(uint256 id, string memory chip, Info memory i) internal pure returns (bytes memory s) {
        uint256 c = uint256(i.chip) % 6;
        s = abi.encodePacked('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="',
            pal(c, true), '"/><stop offset="1" stop-color="#0b0b12"/></linearGradient></defs><rect width="400" height="400" rx="36" fill="url(#g)"/>',
            '<polygon points="200,46 333,123 333,277 200,354 67,277 67,123" fill="#0b0b12" fill-opacity="0.35" stroke="', pal(c, false), '" stroke-width="6"/>');
        for (uint256 k = 0; k < 16; k++) {
            uint256 n = (id >> (k * 8)) & 0xff;
            s = abi.encodePacked(s, '<rect x="', num(144 + (k % 4) * 28), '" y="', num(250 + (k / 4) * 14), '" width="24" height="10" rx="3" fill="',
                pal((c + n) % 6, false), '" opacity="', n > 127 ? "0.95" : "0.35", '"/>');
        }
        s = abi.encodePacked(s, '<text x="200" y="112" text-anchor="middle" font-family="monospace" font-size="20" fill="#fff" opacity="0.8">dsmack</text>',
            '<text x="200" y="200" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-weight="700" font-size="72" fill="#fff">', chip,
            '</text><text x="200" y="232" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="16" fill="#fff" opacity="0.75">Apple silicon, attested</text>',
            '<text x="200" y="384" text-anchor="middle" font-family="monospace" font-size="12" fill="#fff" opacity="0.6">key 0x', hexs(bytes32(id), 4),
            ' / runner 0x', hexs(i.cdhash, 4), '</text></svg>');
    }

    function pal(uint256 k, bool dark) internal pure returns (string memory) {
        string[6] memory bright = ["#5eead4", "#a78bfa", "#f472b6", "#fbbf24", "#60a5fa", "#4ade80"];
        string[6] memory deep = ["#134e4a", "#3b0764", "#500724", "#451a03", "#172554", "#052e16"];
        return dark ? deep[k] : bright[k];
    }

    /// The chip label as the workload wrote it; only [A-Za-z0-9+-] are rendered.
    function label(bytes32 c) internal pure returns (string memory) {
        bytes memory o = new bytes(32);
        uint256 n;
        for (uint256 k = 0; k < 32 && c[k] != 0; k++) {
            bytes1 x = c[k];
            if ((x >= "A" && x <= "Z") || (x >= "a" && x <= "z") || (x >= "0" && x <= "9") || x == "+" || x == "-") o[n++] = x;
        }
        assembly { mstore(o, n) }
        return string(o);
    }

    function num(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        bytes memory o = new bytes(78);
        uint256 n = 78;
        for (; v != 0; v /= 10) o[--n] = bytes1(uint8(48 + v % 10));
        bytes memory r = new bytes(78 - n);
        for (uint256 k = 0; k < r.length; k++) r[k] = o[n + k];
        return string(r);
    }

    function hexs(bytes32 v, uint256 bytes_) internal pure returns (string memory) {
        bytes memory o = new bytes(bytes_ * 2);
        bytes memory d = "0123456789abcdef";
        for (uint256 k = 0; k < bytes_; k++) {
            o[2 * k] = d[uint8(v[k]) >> 4];
            o[2 * k + 1] = d[uint8(v[k]) & 15];
        }
        return string(o);
    }

    function b64(bytes memory d) internal pure returns (string memory) {
        bytes memory t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bytes memory o = new bytes(4 * ((d.length + 2) / 3));
        for (uint256 k = 0; k < d.length; k += 3) {
            uint256 v = uint256(uint8(d[k])) << 16 | (k + 1 < d.length ? uint256(uint8(d[k + 1])) << 8 : 0) | (k + 2 < d.length ? uint256(uint8(d[k + 2])) : 0);
            uint256 j = k / 3 * 4;
            (o[j], o[j + 1]) = (t[v >> 18 & 63], t[v >> 12 & 63]);
            o[j + 2] = k + 1 < d.length ? t[v >> 6 & 63] : bytes1("=");
            o[j + 3] = k + 2 < d.length ? t[v & 63] : bytes1("=");
        }
        return string(o);
    }

    function supportsInterface(bytes4 i) external pure returns (bool) {
        return i == 0x01ffc9a7 || i == 0x80ac58cd || i == 0x5b5e139f;
    }

    function getApproved(uint256) external pure returns (address) {}
    function isApprovedForAll(address, address) external pure returns (bool) {}
    function approve(address, uint256) external pure { revert("non-transferable"); }
    function setApprovalForAll(address, bool) external pure { revert("non-transferable"); }
    function transferFrom(address, address, uint256) external pure { revert("non-transferable"); }
    function safeTransferFrom(address, address, uint256) external pure { revert("non-transferable"); }
    function safeTransferFrom(address, address, uint256, bytes calldata) external pure { revert("non-transferable"); }
}
