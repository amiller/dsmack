"""OCI index membership verification against EXACT index bytes (contract4; D03).

Index membership is VERIFIED, not asserted: the hook consumes the exact
content-addressed index bytes, checks their digest against the requested
pin, selects and validates the platform descriptor, and binds the executed
child to it. A receipt for an index pin carries `index_verification:
"verified"` only when the runner ran this hook against those exact bytes;
membership that was never verified is reported as "unchecked" and cannot
back a completed run's membership claim.

Supported media types are explicit and bounded:

  index/list  : application/vnd.oci.image.index.v1+json
                application/vnd.docker.distribution.manifest.list.v2+json
  child image : application/vnd.oci.image.manifest.v1+json
                application/vnd.docker.distribution.manifest.v2+json

Everything else is rejected fail-closed. The OCI index/manifest JSON is
parsed with the contract's strict parser but is NOT canonicalized: the
bytes are content-addressed, so their exact spelling is what the digest
covers.
"""

from .canonical import load_json_bytes, sha256_hex
from .errors import ContractError, OCIIndexError

SUPPORTED_INDEX_MEDIA_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
SUPPORTED_MANIFEST_MEDIA_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)

MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_INDEX_ENTRIES = 64


def _descriptor_shape(node, path):
    """Structural descriptor check; returns (mediaType, digest, size)."""
    if not isinstance(node, dict) or set(node) - {"mediaType", "digest", "size"}:
        raise OCIIndexError("%s must be an object with exactly {mediaType, digest, size}" % path)
    media = node.get("mediaType")
    if not isinstance(media, str) or not media:
        raise OCIIndexError("%s.mediaType must be a non-empty string" % path)
    digest = node.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71 or any(
        c not in "0123456789abcdef" for c in digest[7:]
    ):
        raise OCIIndexError("%s.digest must be exactly 'sha256:<64 lowercase hex>'" % path)
    size = node.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise OCIIndexError("%s.size must be a positive integer" % path)
    return media, digest, size


def _platform_matches(entry_platform, requested):
    """Requested platform selection semantics.

    os and architecture must match exactly. A requested variant matches only
    entries declaring the same variant; a request without variant accepts
    entries with no variant or with an equal variant.
    """
    if not isinstance(entry_platform, dict):
        return False
    if entry_platform.get("os") != requested.get("os") or entry_platform.get("architecture") != requested.get(
        "architecture"
    ):
        return False
    requested_variant = requested.get("variant")
    entry_variant = entry_platform.get("variant")
    if requested_variant is not None:
        return entry_variant == requested_variant
    return entry_variant in (None, requested_variant)


def verify_index_membership(index_bytes, index_digest, requested_platform):
    """Verify membership of the requested platform in the EXACT index bytes.

    index_bytes: the exact content-addressed index bytes (fetched BY the
      caller through a transport it trusts; this hook verifies content).
    index_digest: the requested pin, 'sha256:<64hex>'; MUST equal
      sha256(index_bytes) -- this is the content-addressed membership root.
    requested_platform: {"os": "linux", "architecture": "amd64"|"arm64",
      "variant": optional str}.

    Returns {"index_digest", "resolved_manifest_digest", "index_entry",
    "membership": "verified"} where index_entry is the EXACT descriptor +
    platform objects from the index bytes. Raises OCIIndexError when the
    bytes do not hash to the pin, the media type is unsupported, the
    platform is absent or ambiguous, or the child descriptor is not an
    image-manifest type.
    """
    if not isinstance(index_digest, str) or not index_digest.startswith("sha256:") or len(index_digest) != 71:
        raise OCIIndexError("index_digest must be exactly 'sha256:<64 hex>'")
    if not isinstance(index_bytes, (bytes, bytearray)):
        raise OCIIndexError("index bytes must be bytes")
    if len(index_bytes) > MAX_INDEX_BYTES:
        raise OCIIndexError("index bytes exceed the %d-byte bound" % MAX_INDEX_BYTES)
    actual = sha256_hex(bytes(index_bytes))
    if actual != index_digest[7:]:
        raise OCIIndexError(
            "index bytes do not hash to the requested index_digest; membership cannot be verified "
            "against content that is not the pinned index (digest mismatch)"
        )
    try:
        doc = load_json_bytes(index_bytes, "oci index", max_bytes=MAX_INDEX_BYTES)
    except ContractError as exc:
        raise OCIIndexError("index bytes are not valid strict JSON: %s" % exc) from None
    if not isinstance(doc, dict) or set(doc) - {"schemaVersion", "mediaType", "manifests", "annotations"}:
        raise OCIIndexError("index document has unsupported top-level keys")
    media = doc.get("mediaType")
    if media not in SUPPORTED_INDEX_MEDIA_TYPES:
        raise OCIIndexError("index mediaType is not a supported index/list type")
    manifests = doc.get("manifests")
    if not isinstance(manifests, list) or not manifests or len(manifests) > MAX_INDEX_ENTRIES:
        raise OCIIndexError("index manifests must be a non-empty list of at most %d entries" % MAX_INDEX_ENTRIES)
    if not isinstance(requested_platform, dict):
        raise OCIIndexError("requested platform must be an object")
    matches = []
    for i, entry in enumerate(manifests):
        if not isinstance(entry, dict):
            raise OCIIndexError("index manifests[%d] must be an object" % i)
        extra = set(entry) - {"mediaType", "digest", "size", "platform", "annotations"}
        if extra:
            raise OCIIndexError("index manifests[%d] has unsupported keys" % i)
        media_i, digest_i, size_i = _descriptor_shape(
            {k: entry.get(k) for k in ("mediaType", "digest", "size")}, "index manifests[%d]" % i
        )
        if media_i not in SUPPORTED_MANIFEST_MEDIA_TYPES:
            continue  # attestation-manifests and unknown children are not candidates
        platform = entry.get("platform")
        if platform is not None and not isinstance(platform, dict):
            raise OCIIndexError("index manifests[%d].platform must be an object or absent" % i)
        if platform is not None and set(platform) - {"os", "architecture", "variant", "os.version", "features"}:
            raise OCIIndexError("index manifests[%d].platform has unsupported keys" % i)
        if platform is not None and _platform_matches(platform, requested_platform):
            matches.append(
                {
                    "descriptor": {"digest": digest_i, "mediaType": media_i, "size": size_i},
                    "platform": {
                        k: platform[k]
                        for k in sorted(set(platform) & {"os", "architecture", "variant"})
                    },
                }
            )
    if not matches:
        raise OCIIndexError("no index entry selects the requested platform")
    if len(matches) > 1:
        raise OCIIndexError("index selection is ambiguous: %d entries match the requested platform" % len(matches))
    entry = matches[0]
    return {
        "index_digest": index_digest,
        "resolved_manifest_digest": entry["descriptor"]["digest"],
        "index_entry": entry,
        "membership": "verified",
    }


__all__ = [
    "SUPPORTED_INDEX_MEDIA_TYPES",
    "SUPPORTED_MANIFEST_MEDIA_TYPES",
    "verify_index_membership",
]
