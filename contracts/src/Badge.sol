// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {IAttestVerifier, ICDRegistry} from "./Canary.sol";

/// Non-transferable ERC721: one badge per App Attest key, minted to the address named by a guest
/// Attest with report_data = reportData(to), from a runner copy registered in CDRegistry under `build`.
/// Token id is the key id. The verifier is an AppleAttestAnyBuildV1 deployed with registry = this contract.
contract Badge {
    struct Attested { bytes32 image; bytes32 manifest; bytes32 run; bytes32 head; bytes32 caller; bytes reportData; }
    bytes constant ATTEST_DOMAIN = "dsmack.appattest.guest-attest/1";
    bytes constant BADGE_DOMAIN = "dsmack.badge.claim/1";
    string public constant name = "dsmack Mac badge";
    string public constant symbol = "DSMACK";
    IAttestVerifier public immutable attest;
    ICDRegistry public immutable cds;
    bytes32 public immutable build;
    mapping(uint256 => address) owners;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    constructor(IAttestVerifier attest_, bytes32 build_) {
        require(build_ != 0, "build");
        (attest, cds, build) = (attest_, attest_.cds(), build_);
    }

    function reportData(address to) public view returns (bytes memory) {
        return abi.encodePacked(sha256(abi.encodePacked(BADGE_DOMAIN, block.chainid, address(this), to)), bytes32(0));
    }

    function claim(address to, Attested calldata a, bytes calldata proof) external returns (uint256 id) {
        require(to != address(0) && keccak256(a.reportData) == keccak256(reportData(to)), "report_data");
        bytes32 kid = attest.verify(sha256(abi.encodePacked(ATTEST_DOMAIN, a.image, a.manifest, a.run, a.head, a.caller, a.reportData)), proof);
        (, bytes32 cdhash,,,) = attest.assertionEvidence(kid);
        require(cds.buildOf(cdhash) == build, "build");
        id = uint256(kid);
        require(owners[id] == address(0), "claimed");
        owners[id] = to;
        balanceOf[to]++;
        emit Transfer(address(0), to, id);
    }

    function ownerOf(uint256 id) public view returns (address o) {
        require((o = owners[id]) != address(0), "no badge");
    }

    function tokenURI(uint256 id) external view returns (string memory) {
        ownerOf(id);
        return 'data:application/json,{"name":"dsmack Mac badge","description":"Claimed by a guest Attest from a dsmack runner on an enrolled Mac."}';
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
