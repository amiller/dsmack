// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface ICDRegistry {
    function buildOf(bytes32 cdhash) external view returns (bytes32);
}

/// AppleAttestAnyBuildV1 deployed with registry = the Canary address.
interface IAttestVerifier {
    function verify(bytes32 context, bytes calldata proof) external returns (bytes32 kid);
    function assertionEvidence(bytes32 kid) external view returns (bytes32 context, bytes32 cdhash, bytes32 rp, uint64 checkedAt, uint32 counter);
    function cds() external view returns (ICDRegistry);
}

/// Self-claiming canaries: each entry pays its funds to the first proof that an isolation
/// boundary broke, and stays burned as public evidence.
/// Each entry pins one CDRegistry build at arm time: assertions count from any re-signed copy
/// registered under it, whatever the registry's current build. That build must never assert
/// caller-chosen data. The funder ends an offer only by `retire`, which leaves NOTICE for claims.
/// A claim after the pot is gone still burns the entry, as evidence with no payout.
/// FORGERY: an App Attest assertion by that build over a context it never asserts.
/// GUEST/RUNNER/OWNER: a P-256 signature over the claimant's address by a per-run canary key
/// whose public key is a system event in a guest Attest assertion by that build. The supervisor
/// sends `canary-guest-key` (key in guest-root tmpfs) before the seal; the app appends
/// `canary-runner-key` (key in its own memory) itself and refuses that name from the guest.
contract Canary {
    enum Kind { Forgery, Guest, Runner, Owner }
    struct Entry { Kind kind; bytes32 build; bytes32 image; bytes32 manifest; address funder; uint64 until; uint256 amount; bool burned; }
    bytes constant FORGERY_DOMAIN = "dsmack.canary.forgery/1";
    bytes constant CLAIM_DOMAIN = "dsmack.canary.claim/1";
    bytes constant ATTEST_DOMAIN = "dsmack.appattest.guest-attest/1";
    /// The guest Attest client-data fields other than the event head.
    struct Attested { bytes32 image; bytes32 manifest; bytes32 run; bytes32 caller; bytes reportData; }
    struct Event { string name; bytes payload; }
    IAttestVerifier public immutable attest;
    ICDRegistry public immutable cds;
    Entry[] public entries;
    /// O(1) lookups for consumers: a burned Guest/Owner entry marks its image, Forgery/Runner its build.
    mapping(bytes32 => bool) public burnedImage;
    mapping(bytes32 => bool) public burnedBuild;
    event Armed(uint256 indexed id, Kind kind, bytes32 build, bytes32 image, bytes32 manifest, uint256 amount, uint64 until);
    event Burned(uint256 indexed id, Kind kind, bytes32 build, bytes32 image, address claimant, uint256 amount);
    event Retired(uint256 indexed id, Kind kind, uint256 amount, uint64 until);
    uint64 public constant NOTICE = 14 days;

    constructor(IAttestVerifier attest_) { (attest, cds) = (attest_, attest_.cds()); }

    /// Entries are append-only; a zero image/manifest admits any. Funds return only after `until`.
    /// Guest/Owner keys live in the guest, so an unbound image would let the owner boot one that leaks its key.
    function arm(Kind kind, bytes32 build, bytes32 image, bytes32 manifest, uint64 until) external payable returns (uint256 id) {
        require(msg.value > 0 && until > block.timestamp && build != 0, "terms");
        require(kind == Kind.Forgery || kind == Kind.Runner || image != 0, "unbound image");
        require(kind != Kind.Owner || manifest != 0, "unbound manifest");
        id = entries.length;
        entries.push(Entry(kind, build, image, manifest, msg.sender, until, msg.value, false));
        emit Armed(id, kind, build, image, manifest, msg.value, until);
    }

    function forgeryContext(uint256 id, address claimant) public view returns (bytes32) {
        return sha256(abi.encodePacked(FORGERY_DOMAIN, block.chainid, address(this), id, claimant));
    }

    function claimDigest(uint256 id, address claimant) public view returns (bytes32) {
        return sha256(abi.encodePacked(CLAIM_DOMAIN, block.chainid, address(this), id, claimant));
    }

    function claimForgery(uint256 id, address payable claimant, bytes calldata proof) external {
        require(entries[id].kind == Kind.Forgery, "kind");
        checkBuild(id, attest.verify(forgeryContext(id, claimant), proof));
        burn(id, claimant);
    }

    /// `a` and the sealed `events` rebuild the client data of the guest Attest assertion `proof`;
    /// (r, s) is the canary key's P-256 signature over claimDigest(id, claimant).
    function claimKey(uint256 id, address payable claimant, Attested calldata a, Event[] calldata events,
                      bytes calldata proof, bytes32 r, bytes32 s) external {
        Entry storage e = entries[id];
        require(e.kind != Kind.Forgery, "kind");
        require((e.image == 0 || e.image == a.image) && (e.manifest == 0 || e.manifest == a.manifest), "not this canary");
        (bytes32 head, bytes calldata key) = canaryKey(e.kind, events);
        checkBuild(id, attest.verify(sha256(abi.encodePacked(ATTEST_DOMAIN, a.image, a.manifest, a.run, head, a.caller, a.reportData)), proof));
        (bool ok, bytes memory res) = address(0x100).staticcall(
            abi.encode(claimDigest(id, claimant), r, s, bytes32(key[:32]), bytes32(key[32:])));
        require(ok && res.length == 32 && abi.decode(res, (uint256)) == 1, "canary signature");
        burn(id, claimant);
    }

    /// Replays the event head. The log must end in its only system-ready and hold exactly one
    /// canary event for `kind`, whose payload is the 64-byte public key x || y.
    function canaryKey(Kind kind, Event[] calldata events) internal pure returns (bytes32 head, bytes calldata key) {
        bytes32 want = keccak256(kind == Kind.Runner ? bytes("canary-runner-key") : bytes("canary-guest-key"));
        uint256 found;
        key = msg.data[0:0];
        for (uint256 i; i < events.length; i++) {
            bytes calldata name = bytes(events[i].name);
            bytes calldata payload = events[i].payload;
            require((keccak256(name) == keccak256("system-ready")) == (i == events.length - 1), "system-ready last");
            if (keccak256(name) == want) {
                require(payload.length == 64, "canary key");
                (key, found) = (payload, found + 1);
            }
            head = sha256(abi.encodePacked(head, sha256(abi.encodePacked(uint32(name.length), name,
                                                                            uint32(payload.length), payload))));
        }
        require(found == 1, "canary event");
    }

    /// Brings `until` to at most NOTICE from now. Claims never close; reclaim opens after `until`.
    function retire(uint256 id) external {
        Entry storage e = entries[id];
        require(msg.sender == e.funder, "funder");
        if (block.timestamp + NOTICE < e.until) e.until = uint64(block.timestamp + NOTICE);
        emit Retired(id, e.kind, e.amount, e.until);
    }

    function reclaim(uint256 id) external {
        Entry storage e = entries[id];
        require(!e.burned && msg.sender == e.funder && block.timestamp > e.until, "reclaim");
        uint256 a = e.amount;
        e.amount = 0;
        (bool ok,) = e.funder.call{value: a}("");
        require(ok, "transfer");
    }

    /// The verified assertion's CDHash must be registered under the entry's build.
    function checkBuild(uint256 id, bytes32 kid) internal view {
        (, bytes32 cdhash,,,) = attest.assertionEvidence(kid);
        require(cds.buildOf(cdhash) == entries[id].build, "build");
    }

    function burn(uint256 id, address payable claimant) internal {
        Entry storage e = entries[id];
        require(!e.burned, "burned");
        uint256 a = e.amount;
        (e.burned, e.amount) = (true, 0);
        if (e.kind == Kind.Guest || e.kind == Kind.Owner) burnedImage[e.image] = true;
        else burnedBuild[e.build] = true;
        emit Burned(id, e.kind, e.build, e.image, claimant, a);
        (bool ok,) = claimant.call{value: a}("");
        require(ok, "transfer");
    }
}
