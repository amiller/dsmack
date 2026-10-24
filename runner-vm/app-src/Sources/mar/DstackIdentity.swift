// DstackIdentity.swift — contract10 image identity + external admission for
// the launch path. Swift port of the
// APPROVED contract10 candidate's lib/dsmack_compose_contract/image_admission.py
// identity surfaces (the parse/verify/admit parts; not the verity tree
// recomputation, which is the guest's in-initrd dm-verity job plus the
// backend's verify-on-open).
//
// THE IDENTITY MAPPING (fable-native-audit F7, made exact here):
//
//   os_image_hash          = sha256(EXACT sha256sum.txt bytes) — the
//                            contract10 / dstack delivered-bundle identity.
//   image_manifest_sha256  = sha256(EXACT image-manifest JSON bytes) — the
//                            launcher-world admission identity (what the
//                            external admission-policy document lists).
//   spec_sha256            = sha256(canonical launch-spec document bytes) —
//                            the launcher-world consumed-tuple digest the
//                            backend records in its receipt (it is NEITHER
//                            of the other two; see LaunchSpecBuilderV3.swift).
//
// The bridge between the first two worlds is the image manifest's
// `provenance.os_image_hash` field — and it is VERIFIED here against the
// recomputed checksum-manifest identity, never trusted. All three digests
// are recorded together in the launch-spec document and in the statement.

import CryptoKit
import Foundation

// MARK: --- delivered dstack checksum manifest (sha256sum.txt)

/// The exact delivered component layout (contract10 COMPONENT_PATHS): the
/// byte layout of this manifest IS what os_image_hash covers; renaming or
/// adding entries changes the identity (no compatibility-by-rename).
let checksumComponentPaths: Set<String> = ["Image", "initramfs.cpio.gz", "metadata.json", "rootfs.squashfs.verity"]

let maxChecksumManifestEntries = 64
let maxChecksumManifestBytes = 65536

/// Parse the exact checksum-manifest bytes. Structural rules (contract10):
/// LF-separated "<64 lowercase hex>  <path>" lines, newline-terminated,
/// bounded count, no duplicates, exactly the delivered component path set,
/// entries sorted by path. Refusals are value-free.
func parseChecksumManifest(_ data: Data) throws -> [String: String] {
    guard data.count <= maxChecksumManifestBytes else {
        throw Fail("checksum manifest is \(data.count) bytes, exceeding the \(maxChecksumManifestBytes)-byte bound")
    }
    let text = String(decoding: data, as: UTF8.self)
    guard text.hasSuffix("\n") else {
        throw Fail("checksum manifest must end with a newline-terminated final line")
    }
    let lines = text.split(separator: "\n", omittingEmptySubsequences: false).dropLast()
    guard !lines.isEmpty, lines.count <= maxChecksumManifestEntries else {
        throw Fail("checksum manifest must hold between 1 and \(maxChecksumManifestEntries) entries")
    }
    var entries: [String: String] = [:]
    var order: [String] = []
    for line in lines {
        let s = String(line)
        guard s.count >= 67 else { throw Fail("checksum manifest line is not '<64hex>  <path>'") }
        let chars = Array(s)
        guard chars[64] == " ", chars[65] == " " else { throw Fail("checksum manifest line is not '<64hex>  <path>'") }
        let digest = String(chars[0..<64])
        let path = String(chars[66...])
        guard isHex64(digest) else { throw Fail("checksum manifest line digest is not 64 lowercase hex") }
        guard checksumComponentPaths.contains(path) else {
            throw Fail("checksum manifest contains a path outside the delivered dstack component layout")
        }
        guard entries[path] == nil else { throw Fail("checksum manifest has a duplicate component path") }
        entries[path] = digest
        order.append(path)
    }
    guard order == order.sorted() else {
        throw Fail("checksum manifest entries must be sorted by path")
    }
    guard Set(entries.keys) == checksumComponentPaths else {
        throw Fail("checksum manifest is missing \(checksumComponentPaths.subtracting(entries.keys).sorted()) delivered component path(s)")
    }
    return entries
}

/// The contract10 image identity: sha256 over the EXACT checksum-manifest bytes.
func osImageHash(_ manifestBytes: Data) -> String {
    sha256hex(manifestBytes)
}

// MARK: --- dstack image metadata (metadata.json)

let dstackMetadataKeys: Set<String> = [
    "kernel", "cmdline", "initrd", "rootfs", "version", "git_revision", "builder",
    "shared_ro", "is_dev", "platform", "os_image_hash_def",
]
let osImageHashDef = "sha256(sha256sum.txt)"
let metadataArch = ["arm64": "aarch64", "amd64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64"]
let maxMetadataBytes = 65536

/// Parse the image metadata under the strict profile: bounded size, exact
/// key set (unknown keys reject — the metadata is part of the authenticated
/// identity), is_dev false (dev images are never admissible).
func parseDstackMetadata(_ data: Data) throws -> [String: Any] {
    guard data.count <= maxMetadataBytes else {
        throw Fail("image metadata exceeds the \(maxMetadataBytes)-byte bound")
    }
    let obj = try JSONSerialization.jsonObject(with: data)
    let d = try requireExactKeys(obj, dstackMetadataKeys, "image metadata")
    for k in ["kernel", "cmdline", "initrd", "rootfs", "version", "git_revision", "builder", "platform", "os_image_hash_def"] {
        _ = try requireNonEmptyString(d, k, "image metadata")
    }
    _ = try strictJSONBool(d["shared_ro"] as Any, "image metadata.shared_ro")
    let isDev = try strictJSONBool(d["is_dev"] as Any, "image metadata.is_dev")
    guard try requireNonEmptyString(d, "os_image_hash_def", "image metadata") == osImageHashDef else {
        throw Fail("image metadata.os_image_hash_def must document the frozen identity derivation")
    }
    guard !isDev else { throw Fail("image metadata.is_dev is true; dev images are never admissible") }
    return d
}

/// Extract '<field>=<value>' from a cmdline (bounded token scan).
func cmdlineField(_ cmdline: String, _ field: String) -> String? {
    for token in cmdline.split(separator: " ") {
        if token.hasPrefix(field + "=") { return String(token.dropFirst(field.count + 1)) }
    }
    return nil
}

// MARK: --- contract10 external admission document

let maxAdmissionBytes = 65536
let admissionVersion = 1

struct ContractAdmission {
    let osImageHash: String
    let admissionSha256: String   // sha256 of the exact admission document bytes
    let version: Int
}

/// Parse {admission_version: 1, allowed_os_image_hashes: [...]} — external
/// configuration OUTSIDE the signed app (ledger 6.4): updating the admitted
/// image set never rebuilds or re-signs the app.
func parseContractAdmission(_ data: Data) throws -> [String] {
    guard data.count <= maxAdmissionBytes else {
        throw Fail("image admission document exceeds the \(maxAdmissionBytes)-byte bound")
    }
    let obj = try JSONSerialization.jsonObject(with: data)
    let d = try requireExactKeys(obj, ["admission_version", "allowed_os_image_hashes"], "image admission")
    let v = try strictJSONInt(d["admission_version"] as Any, "image admission_version")
    guard v == admissionVersion else { throw Fail("image admission_version must be \(admissionVersion)") }
    guard let allowed = d["allowed_os_image_hashes"] as? [String], !allowed.isEmpty else {
        throw Fail("image admission allowed_os_image_hashes must be a non-empty list of strings")
    }
    for h in allowed where !isHex64(h) {
        throw Fail("image admission hashes must be unique 64-hex digests")
    }
    guard Set(allowed).count == allowed.count else {
        throw Fail("image admission hashes must be unique 64-hex digests")
    }
    return allowed
}

/// Fail-closed external admission by checksum identity: the identity set is
/// consulted only AFTER the full boot tuple verifies (verifyImageIdentity).
func admitByOsImageHash(allowed: [String], osImageHash: String, admissionSha256: String) throws -> ContractAdmission {
    guard allowed.contains(osImageHash) else {
        throw Fail("image os_image_hash is not in the external admission set; execution fails closed (no silent substitution, no permissive default)")
    }
    return ContractAdmission(osImageHash: osImageHash, admissionSha256: admissionSha256, version: admissionVersion)
}

// MARK: --- the full identity binding

struct VerifiedImageIdentity {
    let osImageHash: String
    let metadataSha256: String
    let cmdline: String
    let cmdlineSha256: String
    let architecture: String
    let rootfsDataBytes: Int          // dstack.rootfs_size (verity data region)
    let platform: String
}

/// Bind the COMPLETE boot tuple across BOTH identity worlds, fail-closed
/// (contract10 E01 + the launcher manifest):
///   - every launcher-manifest component pin equals the checksum-manifest
///     entry under its DELIVERED name;
///   - metadata bytes hash to the recorded identity (computed here);
///   - metadata cmdline == launcher-manifest cmdline BYTE FOR BYTE;
///   - cmdline dstack.rootfs_hash == manifest verity_root_hash;
///   - dstack.rootfs_size is block-aligned and rootfs_device == /dev/vda;
///   - metadata component names equal the delivered layout;
///   - metadata platform agrees with the manifest arch;
///   - recomputed os_image_hash == manifest.provenance.os_image_hash (the
///     F7 bridge — VERIFIED, never trusted).
func verifyImageIdentity(manifest: ImageManifest, checksumBytes: Data, checksumEntries: [String: String],
                         metadataBytes: Data, metadata: [String: Any]) throws -> VerifiedImageIdentity {
    let pairs: [(String, String, String)] = [
        (manifest.kernel.sha256, checksumEntries["Image"] ?? "", "Image"),
        (manifest.initrd.sha256, checksumEntries["initramfs.cpio.gz"] ?? "", "initramfs.cpio.gz"),
        (manifest.systemDisk.sha256, checksumEntries["rootfs.squashfs.verity"] ?? "", "rootfs.squashfs.verity"),
    ]
    for (pin, entry, path) in pairs where pin != entry {
        throw Fail("manifest component pin does not match the checksum manifest entry for \(path) (image identity is the serialized manifest; the delivered layout IS the identity)")
    }
    // The metadata digest binds the ORIGINAL file bytes (the same discipline
    // as every other admission input: digest over exact bytes, parse
    // separate from identity).
    let metadataDigest = sha256hex(metadataBytes)
    // CROSS-BINDING REPAIR (mac-runtime-seam-repair lane; flagged by
    // mac-compile-followthrough §6). metadata.json is a DELIVERED component of
    // the checksum manifest (its digest is covered by os_image_hash), yet the
    // prior source checked only Image / initramfs.cpio.gz / rootfs.squashfs.verity
    // against their checksum-manifest entries and NEVER bound the authenticated
    // metadata bytes to `checksumEntries["metadata.json"]`. Without this, an
    // attacker holding an admitted os_image_hash could substitute DIFFERENT
    // metadata.json bytes (different cmdline/platform/component names) that
    // this function parses and trusts as "authenticated" — the metadata
    // identity was never actually bound to the admitted bundle. Bind it now,
    // fail-closed, alongside the other delivered components.
    guard let metaEntry = checksumEntries["metadata.json"], metaEntry == metadataDigest else {
        throw Fail("image metadata.json bytes (sha256 \(metadataDigest)) do not match the checksum-manifest metadata.json entry \(checksumEntries["metadata.json"] ?? "<absent>") — the authenticated metadata is part of the delivered dstack identity; no substitution")
    }
    let identity = osImageHash(checksumBytes)
    if let declared = manifest.provenanceOsImageHash, declared != identity {
        throw Fail("manifest.provenance.os_image_hash \(declared) does not equal the recomputed checksum-manifest identity \(identity) — the two identity worlds disagree; refusing")
    }
    let cmdline = manifest.cmdline
    guard let metaCmdline = metadata["cmdline"] as? String, metaCmdline == cmdline else {
        throw Fail("manifest.cmdline does not equal the authenticated metadata cmdline (byte-exact)")
    }
    guard let rootHash = cmdlineField(cmdline, "dstack.rootfs_hash"), isHex64(rootHash) else {
        throw Fail("the metadata cmdline does not carry a 64-hex dstack.rootfs_hash")
    }
    guard rootHash == manifest.verityRootHash else {
        throw Fail("manifest.verity_root_hash does not equal the cmdline dstack.rootfs_hash")
    }
    guard let sizeStr = cmdlineField(cmdline, "dstack.rootfs_size"), let rootfsSize = Int(sizeStr),
          rootfsSize > 0, rootfsSize % 4096 == 0 else {
        throw Fail("the metadata cmdline does not carry a block-aligned dstack.rootfs_size")
    }
    guard cmdlineField(cmdline, "dstack.rootfs_device") == "/dev/vda" else {
        throw Fail("the metadata cmdline dstack.rootfs_device must be /dev/vda")
    }
    for (key, delivered) in [("kernel", "Image"), ("initrd", "initramfs.cpio.gz"), ("rootfs", "rootfs.squashfs.verity")] {
        guard let named = metadata[key] as? String, named == delivered else {
            throw Fail("image metadata.\(key) does not name the delivered \(delivered) entry")
        }
    }
    guard let platform = metadata["platform"] as? String, metadataArch[platform] == manifest.arch else {
        throw Fail("manifest.arch does not agree with the authenticated metadata platform")
    }
    return VerifiedImageIdentity(
        osImageHash: identity,
        metadataSha256: metadataDigest,
        cmdline: cmdline,
        cmdlineSha256: sha256hex(Data(cmdline.utf8)),
        architecture: manifest.arch,
        rootfsDataBytes: rootfsSize,
        platform: platform)
}
