"""dsmack_guest_io — MEASURED guest-image I/O helpers (guest-io-integration).

This package is installed into the measured guest rootfs under
``/usr/local/lib/dsmack/guest-io`` (JOIN-5) and holds the code the trusted
guest supervisor invokes for the generic I/O-continuity delta:

  * ``pt_limits``        — the single source of numeric/grammar bounds for the
                           private-input transport, mirroring (and asserted
                           equal to) the io-contract-reference normative
                           ``dsmack.private-input-transport/1`` constants.
  * ``private_transport``— a real safe bounded ustar parser for the UNMEASURED
                           ``vde`` private-input image.  It REPLACES
                           ``tar -tf`` type inspection and unrestricted root
                           ``tar -x`` with a self-written header parser that
                           fully admits (or refuses) the whole transport
                           BEFORE writing a byte, then extracts into a fresh
                           0700 tree with O_EXCL 0600 files.  No content hash
                           or cache id of any private byte is computed or
                           logged here.
  * ``oci_publish``      — a portable, offline, digest-preserving OCI publisher
                           so the harness image can be served in-guest on the
                           native Mini WITHOUT host Docker or a public upload,
                           while preserving real RepoDigest verification.
  * ``cli``              — the installed ``dsmack-guest-io`` entry point.

Stdlib-only (Python 3.10+); it is deliberately independent of the compose
contract library so it carries no large-input/whole-private-input knowledge.
"""

__all__ = ["pt_limits", "private_transport", "oci_publish", "cli"]
