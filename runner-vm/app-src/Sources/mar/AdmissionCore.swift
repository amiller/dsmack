// AdmissionCore.swift — the app-side admission core (Swift port of the
// launcher admission.py + image_manifest.py + launch_config.py).
//
//   * the signed app is a GENERAL VM launcher/attestor with ZERO compiled-in
//     image identity. Base images are selected by an EXTERNAL image
//     manifest, admitted by an EXTERNAL policy document, and bound by
//     VERIFIED BYTES at launch (kernel/initrd buffers + verify-on-open
//     disks + the exact cmdline). Admitting a new image is a policy edit +
//     a new manifest — never an app rebuild or re-sign.
//   * Structural parsing is kept strictly separate from the admission
//     DECISION: parsing a document never authorizes anything (astra C01).
//   * compose/Claude/task/marketplace policy stays OUTSIDE this core; the
//     workload is untrusted transport content on a read-only disk.

import CryptoKit
import Foundation

// MARK: --- external admission policy (dsmack-general-launcher/admission-policy/1)

let admissionPolicySchema = "dsmack-general-launcher/admission-policy/1"

struct AdmittedImageEntry {
    let imageId: String
    let manifestSha256: String
    let admittedBy: String
}

struct ResourceLimits {
    let maxMemMib: Int
    let maxVcpus: Int
    let maxRuntimeSeconds: Int
}

struct AdmissionPolicy {
    let policyId: String
    let admittedImages: [AdmittedImageEntry]
    let limits: ResourceLimits
    let sha256: String   // sha256 of the exact policy file bytes
}

/// Strictly parse the admission policy bytes; the digest of the EXACT bytes
/// is recorded into every statement (the relying party can recompute it).
func parseAdmissionPolicy(_ data: Data) throws -> AdmissionPolicy {
    let digest = sha256hex(data)
    let obj = try JSONSerialization.jsonObject(with: data)
    let p = try requireExactKeys(obj, ["schema", "policy_id", "admitted_images", "resource_limits", "device_contract", "notes"], "policy")
    guard try requireNonEmptyString(p, "schema", "policy") == admissionPolicySchema else {
        throw Fail("policy schema \(p["schema"] ?? "") != \(admissionPolicySchema)")
    }
    let policyId = try requireNonEmptyString(p, "policy_id", "policy")
    guard let ai = p["admitted_images"] as? [[String: Any]], !ai.isEmpty else {
        throw Fail("policy.admitted_images: non-empty list required")
    }
    var entries: [AdmittedImageEntry] = []
    var seen = Set<String>()
    for e in ai {
        let e = try requireExactKeys(e, ["image_id", "manifest_sha256", "admitted_by"], "policy.admitted_images[]")
        let imageId = try requireNonEmptyString(e, "image_id", "policy.admitted_images[]")
        let h = try requireNonEmptyString(e, "manifest_sha256", "policy.admitted_images[]")
        guard isHex64(h) else { throw Fail("policy.admitted_images[].manifest_sha256: lowercase hex sha256 required") }
        let by = try requireNonEmptyString(e, "admitted_by", "policy.admitted_images[]")
        guard !seen.contains(h) else { throw Fail("policy: duplicate manifest_sha256 in admitted_images") }
        seen.insert(h)
        entries.append(AdmittedImageEntry(imageId: imageId, manifestSha256: h, admittedBy: by))
    }
    let rl = try requireExactKeys(p["resource_limits"] as Any, ["max_mem_mib", "max_vcpus", "max_runtime_seconds"], "policy.resource_limits")
    func lim(_ k: String) throws -> Int {
        let v = try strictJSONInt(rl[k] as Any, "policy.resource_limits.\(k)")
        guard v > 0 else { throw Fail("policy.resource_limits.\(k): positive integer required") }
        return v
    }
    let limits = ResourceLimits(maxMemMib: try lim("max_mem_mib"), maxVcpus: try lim("max_vcpus"), maxRuntimeSeconds: try lim("max_runtime_seconds"))
    _ = try requireExactKeys(p["device_contract"] as Any, ["system", "scratch", "workload"], "policy.device_contract")
    guard p["notes"] is String else { throw Fail("policy.notes: string required") }
    return AdmissionPolicy(policyId: policyId, admittedImages: entries, limits: limits, sha256: digest)
}

struct AdmittedImage {
    let imageId: String
    let manifestSha256: String
    let admittedBy: String
}

/// Admission DECISION (launcher world): the image-manifest FILE digest must
/// be listed by the policy and the manifest's own image_id must match the
/// entry. Content-addressed — a mutated manifest (different bytes/digest)
/// fails even when its image_id is known.
func admitImage(policy: AdmissionPolicy, manifestSha256: String, manifestImageId: String) throws -> AdmittedImage {
    for e in policy.admittedImages where e.manifestSha256 == manifestSha256 {
        guard e.imageId == manifestImageId else {
            throw Fail("manifest digest admitted but image_id \(manifestImageId) != policy entry \(e.imageId)")
        }
        return AdmittedImage(imageId: manifestImageId, manifestSha256: manifestSha256, admittedBy: e.admittedBy)
    }
    throw Fail("image manifest digest \(manifestSha256) is NOT admitted by policy \(policy.policyId) — refusing (fail-closed; parsing never authorizes)")
}

// MARK: --- image manifest (dsmack-general-launcher/image-manifest/1)

let imageManifestSchema = "dsmack-general-launcher/image-manifest/1"

struct ManifestArtifact {
    let path: String
    let sha256: String
    let bytes: Int
}

struct ImageManifest {
    let imageId: String
    let arch: String
    let cmdline: String
    let kernel: ManifestArtifact
    let initrd: ManifestArtifact
    let systemDisk: ManifestArtifact
    let systemFormat: String
    let verityRootHash: String
    let profiles: [String: (memMib: Int, vcpus: Int, basis: String)]
    let supervisorMarkers: String
    let provenanceOsImageHash: String?   // provenance.os_image_hash when present (the F7 bridge)
    let sha256: String                   // sha256 of the exact manifest file bytes
}

let manifestTopFields: Set<String> = ["schema", "image_id", "arch", "description", "cmdline", "kernel", "initrd", "system_disk", "resource_profiles", "guest", "provenance"]

private func parseArtifact(_ v: Any, _ what: String) throws -> ManifestArtifact {
    let d = try requireExactKeys(v, ["path", "sha256", "bytes"], what)
    let path = try requireNonEmptyString(d, "path", what)
    guard path.hasPrefix("/") else { throw Fail("\(what).path: absolute path required") }
    let sha = try requireNonEmptyString(d, "sha256", what)
    guard isHex64(sha) else { throw Fail("\(what).sha256: not a lowercase hex sha256") }
    let bytes = try strictJSONInt(d["bytes"] as Any, "\(what).bytes")
    guard bytes > 0 else { throw Fail("\(what).bytes: positive integer required") }
    return ManifestArtifact(path: path, sha256: sha, bytes: bytes)
}

/// Strictly parse the image manifest. Unknown top-level fields REFUSE (no
/// silent reinterpretation). Artifact paths must exist on this host — the
/// manifest is an identity document, not a suggestion.
func parseImageManifest(_ data: Data) throws -> ImageManifest {
    let digest = sha256hex(data)
    let obj = try JSONSerialization.jsonObject(with: data)
    guard let d = obj as? [String: Any] else { throw Fail("manifest must be a JSON object") }
    let keys = Set(d.keys)
    guard keys.isSubset(of: manifestTopFields) else {
        throw Fail("manifest: unknown top-level fields (fail-closed): \(keys.subtracting(manifestTopFields).sorted())")
    }
    guard manifestTopFields.isSubset(of: keys) else {
        throw Fail("manifest: missing fields: \(manifestTopFields.subtracting(keys).sorted())")
    }
    guard try requireNonEmptyString(d, "schema", "manifest") == imageManifestSchema else {
        throw Fail("manifest schema \(d["schema"] ?? "") != \(imageManifestSchema)")
    }
    let imageId = try requireNonEmptyString(d, "image_id", "manifest")
    let arch = try requireNonEmptyString(d, "arch", "manifest")
    guard arch == "aarch64" || arch == "x86_64" else { throw Fail("manifest.arch \(arch) unsupported by any adapter") }
    _ = try requireNonEmptyString(d, "description", "manifest")
    let cmdline = try requireNonEmptyString(d, "cmdline", "manifest")
    guard printableASCII(cmdline, maxBytes: 2047) else { throw Fail("manifest.cmdline: printable ASCII only, <= 2047 bytes") }
    let kernel = try parseArtifact(d["kernel"] as Any, "manifest.kernel")
    let initrd = try parseArtifact(d["initrd"] as Any, "manifest.initrd")
    let sd = try requireExactKeys(d["system_disk"] as Any, ["path", "sha256", "bytes", "format", "verity_root_hash"], "manifest.system_disk")
    let systemDisk = try parseArtifact(["path": sd["path"] as Any, "sha256": sd["sha256"] as Any, "bytes": sd["bytes"] as Any] as [String: Any], "manifest.system_disk")
    let format = try requireNonEmptyString(sd, "format", "manifest.system_disk")
    let verityRoot = try requireNonEmptyString(sd, "verity_root_hash", "manifest.system_disk")
    guard isHex64(verityRoot) else { throw Fail("manifest.system_disk.verity_root_hash: not a lowercase hex sha256") }
    guard let prof = d["resource_profiles"] as? [String: Any], !prof.isEmpty else {
        throw Fail("manifest.resource_profiles: at least one declared profile required")
    }
    var profiles: [String: (memMib: Int, vcpus: Int, basis: String)] = [:]
    for (name, pv) in prof {
        let pd = try requireExactKeys(pv, ["mem_mib", "vcpus", "basis"], "manifest.resource_profiles['\(name)']")
        let mem = try strictJSONInt(pd["mem_mib"] as Any, "manifest.resource_profiles['\(name)'].mem_mib")
        guard (256...65536).contains(mem) else { throw Fail("profile \(name): mem_mib must be 256..65536") }
        let vcpus = try strictJSONInt(pd["vcpus"] as Any, "manifest.resource_profiles['\(name)'].vcpus")
        guard (1...64).contains(vcpus) else { throw Fail("profile \(name): vcpus must be 1..64") }
        let basis = try requireNonEmptyString(pd, "basis", "manifest.resource_profiles['\(name)']")
        profiles[name] = (mem, vcpus, basis)
    }
    let g = try requireExactKeys(d["guest"] as Any, ["console", "scratch_device", "workload_device", "supervisor_markers"], "manifest.guest")
    let scratchDev = try requireNonEmptyString(g, "scratch_device", "manifest.guest")
    let workloadDev = try requireNonEmptyString(g, "workload_device", "manifest.guest")
    guard scratchDev == "vdb", workloadDev == "vdc" else {
        throw Fail("manifest.guest device contract must be scratch=vdb, workload=vdc (pinned supervisor)")
    }
    let markers = try requireNonEmptyString(g, "supervisor_markers", "manifest.guest")
    guard let prov = d["provenance"] as? [String: Any], !prov.isEmpty else {
        throw Fail("manifest.provenance: non-empty object required (source lane / build facts)")
    }
    let provHash = prov["os_image_hash"] as? String   // optional bridge; verified when the checksum manifest is supplied
    if let h = provHash, !isHex64(h) { throw Fail("manifest.provenance.os_image_hash: not a lowercase hex sha256") }
    // Artifact paths must exist before anything is staged (fail-closed).
    for a in [kernel, initrd, systemDisk] where !FileManager.default.fileExists(atPath: a.path) {
        throw Fail("manifest artifact path missing on this host: \(a.path)")
    }
    return ImageManifest(imageId: imageId, arch: arch, cmdline: cmdline, kernel: kernel, initrd: initrd,
                         systemDisk: systemDisk, systemFormat: format, verityRootHash: verityRoot,
                         profiles: profiles, supervisorMarkers: markers, provenanceOsImageHash: provHash, sha256: digest)
}

// MARK: --- launch resolution (admitted image x declared profile x policy caps)

struct LaunchPlan {
    let imageId: String
    let manifestSha256: String
    let admittedBy: String
    let arch: String
    let profileName: String
    let profileBasis: String
    let memMib: Int
    let vcpus: Int
    let runtimeSeconds: Int
    let cmdline: String
    let verityRootHash: String
}

/// Resolve the launch plan or refuse. The profile must be DECLARED BY THE
/// IMAGE (measured basis — ledger 13.2; the 512 MiB guess is never silently
/// retained for a Node+Docker image) and must fit the POLICY caps (external
/// budget). The runtime bound is the minimum of the policy cap and the
/// caller request — never above either.
func resolveLaunch(manifest: ImageManifest, admission: AdmittedImage, policy: AdmissionPolicy,
                   profileName: String, requestedRuntimeSeconds: Int) throws -> LaunchPlan {
    guard let p = manifest.profiles[profileName] else {
        throw Fail("profile \(profileName) not declared by image \(manifest.imageId) (declared: \(manifest.profiles.keys.sorted())); refusing rather than guessing resources")
    }
    var over: [String] = []
    if p.memMib > policy.limits.maxMemMib { over.append("mem_mib \(p.memMib) > policy \(policy.limits.maxMemMib)") }
    if p.vcpus > policy.limits.maxVcpus { over.append("vcpus \(p.vcpus) > policy \(policy.limits.maxVcpus)") }
    guard over.isEmpty else { throw Fail("declared profile exceeds policy budget: \(over.joined(separator: "; "))") }
    let runtime = min(requestedRuntimeSeconds, policy.limits.maxRuntimeSeconds)
    guard runtime > 0 else { throw Fail("runtime bound must be positive") }
    return LaunchPlan(imageId: admission.imageId, manifestSha256: admission.manifestSha256,
                      admittedBy: admission.admittedBy, arch: manifest.arch, profileName: profileName,
                      profileBasis: p.basis, memMib: p.memMib, vcpus: p.vcpus, runtimeSeconds: runtime,
                      cmdline: manifest.cmdline, verityRootHash: manifest.verityRootHash)
}
