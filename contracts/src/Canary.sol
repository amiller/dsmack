// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// AppleAttestRegistryV1 deployed with registry = the Canary address.
interface IAttestVerifier {
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32);
}

/// Self-claiming canaries: each entry pays its funds to the first proof that an isolation
/// boundary broke, and stays burned as public evidence.
/// FORGERY: an App Attest assertion over a context no approved build ever asserts.
/// GUEST/RUNNER/OWNER: a signature by a per-run key that the approved app asserted it kept
/// inside the boundary, over the claimant's address.
contract Canary {
    enum Kind { Forgery, Guest, Runner, Owner }
    struct Entry { Kind kind; bytes32 image; bytes32 manifest; address funder; uint64 until; uint256 amount; bool burned; }
    bytes constant FORGERY_DOMAIN = "dsmack.canary.forgery/1";
    bytes constant KEY_DOMAIN = "dsmack.canary.key/1";
    IAttestVerifier public immutable attest;
    Entry[] public entries;
    event Armed(uint256 indexed id, Kind kind, bytes32 image, bytes32 manifest, uint256 amount, uint64 until);
    event Burned(uint256 indexed id, Kind kind, address claimant, uint256 amount);

    constructor(IAttestVerifier attest_) { attest = attest_; }

    /// Entries are append-only; a zero image/manifest admits any. Funds return only after `until`.
    function arm(Kind kind, bytes32 image, bytes32 manifest, uint64 until) external payable returns (uint256 id) {
        require(msg.value > 0 && until > block.timestamp, "terms");
        id = entries.length;
        entries.push(Entry(kind, image, manifest, msg.sender, until, msg.value, false));
        emit Armed(id, kind, image, manifest, msg.value, until);
    }

    function forgeryContext(uint256 id, address claimant) public view returns (bytes32) {
        return sha256(abi.encodePacked(FORGERY_DOMAIN, block.chainid, address(this), id, claimant));
    }

    /// The context the app asserts when it reports a canary key it generated for `kind`.
    function keyContext(Kind kind, bytes32 image, bytes32 manifest, address key) public pure returns (bytes32) {
        return sha256(abi.encodePacked(KEY_DOMAIN, uint8(kind), image, manifest, key));
    }

    function claimDigest(uint256 id, address claimant) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",
            keccak256(abi.encodePacked(block.chainid, address(this), id, claimant))));
    }

    function claimForgery(uint256 id, address payable claimant, bytes calldata proof) external {
        require(entries[id].kind == Kind.Forgery, "kind");
        attest.verify(forgeryContext(id, claimant), proof);
        burn(id, claimant);
    }

    function claimKey(uint256 id, address payable claimant, bytes32 image, bytes32 manifest, address key,
                      bytes calldata proof, uint8 v, bytes32 r, bytes32 s) external {
        Entry storage e = entries[id];
        require(e.kind != Kind.Forgery, "kind");
        require((e.image == 0 || e.image == image) && (e.manifest == 0 || e.manifest == manifest), "not this canary");
        require(key != address(0) && ecrecover(claimDigest(id, claimant), v, r, s) == key, "canary signature");
        attest.verify(keyContext(e.kind, image, manifest, key), proof);
        burn(id, claimant);
    }

    function reclaim(uint256 id) external {
        Entry storage e = entries[id];
        require(!e.burned && msg.sender == e.funder && block.timestamp > e.until, "reclaim");
        uint256 a = e.amount;
        e.amount = 0;
        (bool ok,) = e.funder.call{value: a}("");
        require(ok, "transfer");
    }

    function burn(uint256 id, address payable claimant) internal {
        Entry storage e = entries[id];
        require(!e.burned && e.amount > 0, "burned");
        uint256 a = e.amount;
        (e.burned, e.amount) = (true, 0);
        emit Burned(id, e.kind, claimant, a);
        (bool ok,) = claimant.call{value: a}("");
        require(ok, "transfer");
    }
}
