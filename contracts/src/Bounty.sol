// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {IAttestVerifier, ICDRegistry} from "./Canary.sol";

/// Pays an entry to the first payee named by a guest Attest of the entry's pinned checker workload.
/// The checker (image, manifest, caller service) attests only after its fixed test passes on the
/// candidate commit, with report_data = reportData(id, payee, commit), so a relayer cannot redirect it.
/// The assertion must come from a runner copy registered in CDRegistry under the entry's build.
/// The verifier is an AppleAttestAnyBuildV1 deployed with registry = this contract.
contract Bounty {
    struct Entry { bytes32 build; bytes32 image; bytes32 manifest; bytes32 caller; address funder; uint64 until; uint256 amount; bool paid; }
    struct Attested { bytes32 image; bytes32 manifest; bytes32 run; bytes32 head; bytes32 caller; bytes reportData; }
    bytes constant ATTEST_DOMAIN = "dsmack.appattest.guest-attest/1";
    bytes constant BOUNTY_DOMAIN = "dsmack.bounty.claim/1";
    IAttestVerifier public immutable attest;
    ICDRegistry public immutable cds;
    Entry[] public entries;
    event Posted(uint256 indexed id, bytes32 build, bytes32 image, bytes32 manifest, bytes32 caller, uint256 amount, uint64 until);
    event Claimed(uint256 indexed id, address payee, bytes20 commit, bytes32 kid, uint256 amount);

    constructor(IAttestVerifier attest_) { (attest, cds) = (attest_, attest_.cds()); }

    function post(bytes32 build, bytes32 image, bytes32 manifest, bytes32 caller, uint64 until) external payable returns (uint256 id) {
        require(msg.value > 0 && until > block.timestamp && build != 0 && image != 0 && manifest != 0 && caller != 0, "terms");
        id = entries.length;
        entries.push(Entry(build, image, manifest, caller, msg.sender, until, msg.value, false));
        emit Posted(id, build, image, manifest, caller, msg.value, until);
    }

    function reportData(uint256 id, address payee, bytes20 commit) public view returns (bytes memory) {
        return abi.encodePacked(sha256(abi.encodePacked(BOUNTY_DOMAIN, block.chainid, address(this), id, payee, commit)), bytes32(0));
    }

    function claim(uint256 id, address payable payee, bytes20 commit, Attested calldata a, bytes calldata proof) external {
        Entry storage e = entries[id];
        require(!e.paid, "paid");
        require(a.image == e.image && a.manifest == e.manifest && a.caller == e.caller, "not this checker");
        require(keccak256(a.reportData) == keccak256(reportData(id, payee, commit)), "report_data");
        bytes32 kid = attest.verify(sha256(abi.encodePacked(ATTEST_DOMAIN, a.image, a.manifest, a.run, a.head, a.caller, a.reportData)), proof);
        (, bytes32 cdhash,,,) = attest.assertionEvidence(kid);
        require(cds.buildOf(cdhash) == e.build, "build");
        uint256 amount = e.amount;
        (e.paid, e.amount) = (true, 0);
        emit Claimed(id, payee, commit, kid, amount);
        (bool ok,) = payee.call{value: amount}("");
        require(ok, "transfer");
    }

    function reclaim(uint256 id) external {
        Entry storage e = entries[id];
        require(!e.paid && msg.sender == e.funder && block.timestamp > e.until, "reclaim");
        uint256 amount = e.amount;
        (e.paid, e.amount) = (true, 0);
        (bool ok,) = e.funder.call{value: amount}("");
        require(ok, "transfer");
    }
}
