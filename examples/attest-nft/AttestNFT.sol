// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {IAttestVerifier, ICDRegistry} from "dsmack/Canary.sol";

/// One non-transferable token per Apple chip. The approved app reads the chip's model, its chip-id and
/// its ECID (unique-chip-id) from macOS and signs context(...) with its App Attest key, sending only
/// device = sha256(DEVICE_DOMAIN || this || ECID). The verifier checks Apple's signature; this contract
/// requires the signing copy's CDHash to be registered under `build`, whoever signed that copy. Deploy the
/// verifier (AppleAttestAnyBuildV1) with registry = this contract's address.
contract AttestNFT {
    bytes constant DOMAIN = "dsmack.example.attest-nft/2";
    string public constant name = "Attested Mac";
    string public constant symbol = "AMAC";
    IAttestVerifier public immutable attest;
    ICDRegistry public immutable cds;
    bytes32 public immutable build;
    struct Info { bytes32 chip; uint32 chipId; bytes32 device; bytes32 cdhash; }
    mapping(uint256 => address) owners;
    mapping(uint256 => Info) public info;
    mapping(bytes32 => uint256) public tokenOfDevice;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    constructor(IAttestVerifier attest_, bytes32 build_) {
        (attest, cds, build) = (attest_, attest_.cds(), build_);
    }

    function context(address to, bytes32 chip, uint32 chipId, bytes32 device) public view returns (bytes32) {
        return sha256(abi.encodePacked(DOMAIN, block.chainid, address(this), to, chip, chipId, device));
    }

    /// Token id = device, so one chip holds one token however many App Attest keys it makes.
    function claim(address to, bytes32 chip, uint32 chipId, bytes32 device, bytes calldata proof) external returns (uint256 id) {
        bytes32 kid = attest.verify(context(to, chip, chipId, device), proof);
        (, bytes32 cdhash,,,) = attest.assertionEvidence(kid);
        require(cds.buildOf(cdhash) == build, "build");
        id = uint256(device);
        require(owners[id] == address(0), "claimed");
        owners[id] = to;
        info[id] = Info(chip, chipId, device, cdhash);
        balanceOf[to]++;
        emit Transfer(address(0), to, id);
    }

    function ownerOf(uint256 id) public view returns (address o) {
        require((o = owners[id]) != address(0), "no token");
    }

    function tokenURI(uint256 id) external view returns (string memory) {
        ownerOf(id);
        Info memory i = info[id];
        string memory chip = label(i.chip);
        bytes memory json = abi.encodePacked('{"name":"Attested Mac: ', chip, '","description":"One per Apple chip. The approved app read the chip from macOS and signed it with an App Attest key; Apple, the code rule and the one-per-chip rule are checked on chain.","attributes":[{"trait_type":"Chip","value":"',
            chip, '"},{"trait_type":"chip-id","value":"0x', hexs(bytes32(uint256(i.chipId) << 224), 4), '"},{"trait_type":"App CDHash","value":"0x', hexs(i.cdhash, 4),
            '"}],"image":"data:image/svg+xml;base64,', b64(svg(chip, i)), '"}');
        return string(abi.encodePacked("data:application/json;utf8,", json));
    }

    /// A die drawn from the chip: a 12x12 grid of cores, a quarter of them lit by the device hash.
    function svg(string memory chip, Info memory i) internal pure returns (bytes memory s) {
        uint256 c = uint256(i.chipId) % 6;
        s = abi.encodePacked('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400"><defs><pattern id="g" x="92" y="92" width="18" height="18" patternUnits="userSpaceOnUse">',
            '<rect width="14" height="14" rx="3" fill="#ffffff" fill-opacity="0.13"/></pattern></defs><rect width="400" height="400" fill="#0b0b12"/>',
            '<rect x="60" y="60" width="280" height="280" rx="18" fill="', pal(c, true), '" stroke="', pal(c, false), '" stroke-width="4"/>',
            '<path d="M84 40h12v20h-12zM120 40h12v20h-12zM156 40h12v20h-12zM192 40h12v20h-12zM228 40h12v20h-12zM264 40h12v20h-12zM300 40h12v20h-12z',
            'M84 340h12v20h-12zM120 340h12v20h-12zM156 340h12v20h-12zM192 340h12v20h-12zM228 340h12v20h-12zM264 340h12v20h-12zM300 340h12v20h-12z" fill="#9ca3af"/>',
            '<path d="M40 84v12h20v-12zM40 120v12h20v-12zM40 156v12h20v-12zM40 192v12h20v-12zM40 228v12h20v-12zM40 264v12h20v-12zM40 300v12h20v-12z',
            'M340 84v12h20v-12zM340 120v12h20v-12zM340 156v12h20v-12zM340 192v12h20v-12zM340 228v12h20v-12zM340 264v12h20v-12zM340 300v12h20v-12z" fill="#9ca3af"/>',
            '<rect x="92" y="92" width="212" height="212" fill="url(#g)"/>');
        bytes32 h = keccak256(abi.encodePacked(i.device));
        for (uint256 r = 0; r < 12; r++) {
            bytes memory row = abi.encodePacked('<g fill="', pal((c + r) % 6, false), '">');
            for (uint256 k = r * 12; k < r * 12 + 12; k++) {
                if ((uint256(k < 128 ? i.device : h) >> (k % 128 * 2)) & 3 == 3) {
                    row = abi.encodePacked(row, '<rect x="', num(92 + (k % 12) * 18), '" y="', num(92 + r * 18), '" width="14" height="14" rx="3"/>');
                }
            }
            s = abi.encodePacked(s, row, '</g>');
        }
        s = abi.encodePacked(s, '<text x="200" y="384" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-weight="700" font-size="22" fill="#fff">', chip,
            '</text><text x="200" y="28" text-anchor="middle" font-family="monospace" font-size="12" fill="#fff" opacity="0.6">chip 0x', hexs(i.device, 4), ' / app 0x', hexs(i.cdhash, 4), '</text></svg>');
    }

    function pal(uint256 k, bool dark) internal pure returns (string memory) {
        string[6] memory bright = ["#5eead4", "#a78bfa", "#f472b6", "#fbbf24", "#60a5fa", "#4ade80"];
        string[6] memory deep = ["#134e4a", "#3b0764", "#500724", "#451a03", "#172554", "#052e16"];
        return dark ? deep[k] : bright[k];
    }

    /// The chip name as the app read it; only [A-Za-z0-9 +-] are rendered.
    function label(bytes32 c) internal pure returns (string memory) {
        bytes memory o = new bytes(32);
        uint256 n;
        for (uint256 k = 0; k < 32 && c[k] != 0; k++) {
            bytes1 x = c[k];
            if ((x >= "A" && x <= "Z") || (x >= "a" && x <= "z") || (x >= "0" && x <= "9") || x == " " || x == "+" || x == "-") o[n++] = x;
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
}
