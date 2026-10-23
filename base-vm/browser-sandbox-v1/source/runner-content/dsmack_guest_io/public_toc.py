"""GIO03: STRUCTURED admission of the measured public workload archive (vdc).

The trusted guest supervisor used to admit the vdc table-of-contents by text
parsing ``tar tvf`` output -- reading the typeflag from ``cut -c1`` and the
member name from ``awk '{print $NF}'``.  ``awk '{print $NF}'`` takes only the
LAST whitespace-separated field, so a member name CONTAINING WHITESPACE (e.g.
``manifests/a b.json``) is mis-split and the admitted name differs from the
real one; the same text listing cannot reliably recover the exact set of
dot-prefixed (hidden) entries either.  A forged vdc could therefore smuggle a
member past the admission that the later ``tar xf`` would still extract.

This module admits the archive from its TAR HEADERS instead: it enumerates
``tarfile`` members and checks the EXACT typeflag (regular file or directory
only) and the EXACT name (absolute / ``..`` traversal refused, every top-level
segment confined to the public-channel allowlist), handling whitespace and
hidden entries exactly.  It is MEASURED guest-image bytes (stdlib ``tarfile``
only) and writes NOTHING -- it is a pure pre-extraction admission decision,
mirroring the private-transport parser's admit-before-write discipline.
"""
from __future__ import annotations

import tarfile

#: The public channels + top-level marker files a measured vdc may carry.
PUBLIC_TOP_LEVEL = frozenset({
    "manifests", "admission", "base-bundle", "images", "commitments",
    "oci-layout", "closure-context", "public-inputs", "WORKLOAD", "SHA256SUMS",
})


class PublicTocRefusal(Exception):
    """Fail-closed refusal of the public vdc archive.  The string names the
    rule and the offending member name (never member content)."""

    def __init__(self, rule: str, detail: str = ""):
        self.rule = rule
        self.detail = detail
        super().__init__(rule if not detail else "%s %s" % (rule, detail))


def _refuse_path(name: str) -> bool:
    return (name.startswith("/") or name == ".." or name.startswith("../")
            or "/../" in name or name.endswith("/.."))


def _effective_top(name: str):
    """GIO03 (repair3-review): compute the EFFECTIVE top-level channel segment
    of a member name, after NORMALIZING leading/interior ``.`` and empty
    segments, so a ``./``-prefixed name cannot bypass the channel allowlist.

    The previous admitter took ``top = name.split('/', 1)[0]`` and treated a
    top of ``'.'`` as the archive root (``continue``), so ``./envelopes/secret``,
    ``./broker/key`` and ``./.secret`` all skipped the allowlist and proceeded
    to extraction.  Here every ``'.'`` / empty segment is dropped FIRST; only a
    name with NO remaining effective segment (``.`` / ``./`` / ``././`` -- a
    genuine archive-root directory entry, which is not a channel) returns
    ``None`` and bypasses the channel check.  Any other name's channel is its
    FIRST non-dot segment, so a leading ``./`` on a private or hidden entry is
    normalized away before the allowlist is consulted ('./.secret' -> top
    '.secret'; './envelopes/x' -> top 'envelopes')."""
    effective = [seg for seg in name.split("/") if seg not in ("", ".")]
    if not effective:
        return None
    return effective[0]


def admit_members(members):
    """Admit an iterable of ``tarfile.TarInfo`` members.  Returns the admitted
    count.  Raises ``PublicTocRefusal`` on the FIRST violation (no partial
    acceptance).  ``members`` are consumed from the tar headers, so names are
    exact -- whitespace and hidden entries included."""
    admitted = 0
    for m in members:
        name = m.name
        # EXACT type: a regular file or a directory only; any link / symlink /
        # device / fifo / block / char member is refused.
        if not (m.isreg() or m.isdir()):
            raise PublicTocRefusal("public_toc_bad_member_type",
                                   "%r (type=%r)" % (name, m.type))
        if _refuse_path(name):
            raise PublicTocRefusal("public_toc_bad_member_path", repr(name))
        # GIO03: normalize dot-prefixed paths BEFORE checking the effective
        # top-level channel.  Only an actual archive-root directory entry (no
        # effective segment) bypasses the channel check; every other name --
        # including a ./-prefixed hidden or private-channel entry -- is checked
        # against the public-channel allowlist by its first non-dot segment.
        top = _effective_top(name)
        if top is None:
            continue
        if top not in PUBLIC_TOP_LEVEL:
            raise PublicTocRefusal("public_toc_unadmitted_channel",
                                   "top-level %r (member %r)" % (top, name))
        admitted += 1
    return admitted


def admit_archive(archive_path: str) -> int:
    """Open ``archive_path`` (a raw uncompressed ustar stream at offset 0 -- the
    vdc device or an image file) and admit its members structurally.  Returns
    the admitted member count; raises ``PublicTocRefusal`` on any violation or
    on a corrupt/unreadable archive (fail closed)."""
    try:
        tf = tarfile.open(archive_path, "r:")
    except (tarfile.TarError, OSError) as exc:
        raise PublicTocRefusal("public_toc_unreadable_archive", type(exc).__name__) from exc
    try:
        try:
            return admit_members(tf)
        except tarfile.TarError as exc:
            raise PublicTocRefusal("public_toc_corrupt_header", type(exc).__name__) from exc
    finally:
        tf.close()
