// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {AttestNFT} from "../AttestNFT.sol";
import {IAttestVerifier, ICDRegistry} from "dsmack/Canary.sol";

/// Stands in for AppleAttestAnyBuildV1 + CDRegistry: proof = (signed context, cdhash).
contract MockAttest is IAttestVerifier, ICDRegistry {
    mapping(bytes32 => bytes32) public buildOf;
    mapping(bytes32 => bytes32) evidence;
    function admit(bytes32 cdhash, bytes32 b) external { buildOf[cdhash] = b; }
    function cds() external view returns (ICDRegistry) { return this; }
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32 kid) {
        (bytes32 signed, bytes32 cdhash) = abi.decode(proof, (bytes32, bytes32));
        require(signed == context, "assertion signature");
        require(buildOf[cdhash] != 0, "build not admitted");
        kid = keccak256(abi.encode(cdhash));
        evidence[kid] = cdhash;
    }
    function assertionEvidence(bytes32 kid) external view returns (bytes32, bytes32, bytes32, uint64, uint32) {
        return (0, evidence[kid], 0, 0, 0);
    }
}

contract AttestNFTTest is Test {
    AttestNFT n;
    address alice = address(0xA11CE);
    address mallory = address(0xBAD);
    bytes32 constant APP = keccak256("app cdhash");
    bytes32 constant RESIGNED = keccak256("app re-signed by another team");
    bytes32 constant OTHER = keccak256("another program");
    bytes32 constant BUILD = keccak256("approved build");
    bytes32 constant CHIP = "Apple M4 Pro";
    uint32 constant CHIP_ID = 0x6040;
    bytes32 constant MAC = keccak256("device tag of one Mac");

    function setUp() public {
        MockAttest m = new MockAttest();
        m.admit(APP, BUILD);
        m.admit(RESIGNED, BUILD);
        m.admit(OTHER, keccak256("other build"));
        n = new AttestNFT(m, BUILD);
    }

    function proof(address to, bytes32 device, bytes32 cdhash) internal view returns (bytes memory) {
        return abi.encode(n.context(to, CHIP, CHIP_ID, device), cdhash);
    }

    function test_anyoneSubmitsMintsToSignedRecipient() public {
        bytes memory pf = proof(alice, MAC, RESIGNED);
        vm.prank(mallory);
        uint256 id = n.claim(alice, CHIP, CHIP_ID, MAC, pf);
        assertEq(id, uint256(MAC));
        assertEq(n.ownerOf(id), alice);
        assertEq(n.balanceOf(alice), 1);
        (bytes32 chip, uint32 chipId,, bytes32 cdhash) = n.info(id);
        assertEq(chip, CHIP);
        assertEq(chipId, CHIP_ID);
        assertEq(cdhash, RESIGNED);
    }

    function test_submitterCannotRedirectOrRelabel() public {
        bytes memory pf = proof(alice, MAC, APP);
        vm.expectRevert("assertion signature");
        n.claim(mallory, CHIP, CHIP_ID, MAC, pf);
        vm.expectRevert("assertion signature");
        n.claim(alice, "Apple M9 Ultra", CHIP_ID, MAC, pf);
    }

    /// A second App Attest key on the same Mac (here: another signed copy) cannot claim again.
    function test_oneTokenPerChip() public {
        n.claim(alice, CHIP, CHIP_ID, MAC, proof(alice, MAC, APP));
        bytes memory pf = proof(mallory, MAC, RESIGNED);
        vm.expectRevert("claimed");
        n.claim(mallory, CHIP, CHIP_ID, MAC, pf);
    }

    function test_otherBuildRefused() public {
        bytes memory pf = proof(alice, MAC, OTHER);
        vm.expectRevert("build");
        n.claim(alice, CHIP, CHIP_ID, MAC, pf);
    }

    function test_contextBindsEverything() public view {
        assertEq(n.context(alice, CHIP, CHIP_ID, MAC), sha256(abi.encodePacked("dsmack.example.attest-nft/2", block.chainid, address(n), alice, CHIP, CHIP_ID, MAC)));
    }

    function test_tokenURIRendersChip() public {
        uint256 id = n.claim(alice, CHIP, CHIP_ID, MAC, proof(alice, MAC, APP));
        string memory uri = n.tokenURI(id);
        assertGt(bytes(uri).length, 1000);
        vm.writeFile("out/token-uri.txt", uri);
    }
}
