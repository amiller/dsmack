"""Portable, offline, digest-preserving OCI publisher (measured guest image).

PROBLEM (NATIVE-NETWORK-INTEGRATION.json): on the native Mini there is no host
Docker and no public registry, and the old Zed ``10.0.2.2:5005`` host-loopback
registry is not reachable.  ``docker load`` + retag is NOT sufficient: a loaded
image gets a local ID but NO RepoDigest, so the runner's real pull-by-digest /
RepoDigest verification cannot be satisfied.

SOLUTION: carry the harness image as a CONTENT-ADDRESSED OCI image layout
(``index.json`` + ``blobs/sha256/<hex>``) inside the measured ``vdc`` public
workload, and serve it to the in-guest dockerd from a minimal, READ-ONLY,
loopback-only OCI Distribution v2 registry implemented HERE in measured guest
bytes.  The guest then runs ``docker pull 127.0.0.1:<port>/<name>@sha256:<D>``
and gets back EXACTLY the manifest digest ``D`` as its RepoDigest — real
RepoDigest verification is preserved, with no host Docker, no public upload and
no caller-provided helper executed.

This module:
  * fully verifies the OCI layout (every manifest/config/layer blob present and
    byte-hashing to its digest) BEFORE serving — fail closed;
  * serves ONLY GET/HEAD for ``/v2/``, ``/v2/<name>/manifests/<ref>`` and
    ``/v2/<name>/blobs/<digest>`` on an explicit loopback host; every response
    body is re-verified to hash to the requested digest (manifests/blobs by
    digest) so a corrupted layout can never be served as a valid digest;
  * never writes, never accepts uploads, never reaches the network.

The real child-image digests of the final demo image are still produced by the
later real build; this publisher is the transport, not the image.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Bounds (a layout larger than this fails closed rather than being served).
OCI_BLOB_BYTES_MAX = 1 << 30            # 1 GiB per blob
OCI_TOTAL_BYTES_MAX = 4 << 30           # 4 GiB total layout
OCI_MANIFEST_BYTES_MAX = 4 << 20        # 4 MiB per manifest/index document (parsed JSON)
OCI_INDEX_BYTES_MAX = 4 << 20           # 4 MiB top-level index.json
OCI_MANIFEST_DEPTH_MAX = 4              # index -> manifest-list -> manifest -> (config/layers)
OCI_DESCRIPTOR_COUNT_MAX = 4096         # total manifests + config + layer descriptors visited
OCI_VERIFY_SECONDS = 120               # whole-layout verification deadline
OCI_MANIFEST_MEDIA_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
_DIGEST_RE = None  # compiled lazily


def _digest_ok(digest: str) -> bool:
    global _DIGEST_RE
    if _DIGEST_RE is None:
        import re
        _DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
    return bool(_DIGEST_RE.match(digest))


class LayoutError(Exception):
    """Fail-closed rejection of an OCI image layout."""


def _blob_path(layout_dir: str, digest: str) -> str:
    if not _digest_ok(digest):
        raise LayoutError("bad-digest-form %s" % digest)
    return os.path.join(layout_dir, "blobs", "sha256", digest.split(":", 1)[1])


def _read_blob(layout_dir: str, digest: str, cap: int = OCI_BLOB_BYTES_MAX) -> bytes:
    path = _blob_path(layout_dir, digest)
    st = os.lstat(path)
    if not os.path.stat.S_ISREG(st.st_mode):
        raise LayoutError("blob-not-regular %s" % digest)
    if st.st_size > cap:
        raise LayoutError("blob-too-large %s" % digest)
    with open(path, "rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise LayoutError("blob-too-large %s" % digest)
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise LayoutError("blob-digest-mismatch want=%s got=%s" % (digest, actual))
    return data


def verify_layout(layout_dir: str) -> dict:
    """Fully verify an OCI image layout and return a served model:
    {names: {name: manifest_digest}, manifests: {digest: media_type},
     blobs: set(digest)}.  Every referenced blob must exist and hash to its
    digest; any mismatch is a fail-closed LayoutError."""
    index_path = os.path.join(layout_dir, "index.json")
    st = os.lstat(index_path)
    if not os.path.stat.S_ISREG(st.st_mode):
        raise LayoutError("index-not-regular")
    if st.st_size > OCI_INDEX_BYTES_MAX:
        raise LayoutError("index-too-large")
    with open(index_path, "rb") as handle:
        raw_index = handle.read(OCI_INDEX_BYTES_MAX + 1)
    if len(raw_index) > OCI_INDEX_BYTES_MAX:
        raise LayoutError("index-too-large")
    index = json.loads(raw_index)
    names: dict = {}
    manifests: dict = {}
    blobs: set = set()
    total = [0]
    descriptors = [0]
    visited: set = set()
    deadline = time.monotonic() + OCI_VERIFY_SECONDS

    def tick():
        if time.monotonic() > deadline:
            raise LayoutError("verify-deadline")
        descriptors[0] += 1
        if descriptors[0] > OCI_DESCRIPTOR_COUNT_MAX:
            raise LayoutError("descriptor-count")

    def account(digest: str, data: bytes):
        if digest not in blobs:
            blobs.add(digest)
            total[0] += len(data)
            if total[0] > OCI_TOTAL_BYTES_MAX:
                raise LayoutError("layout-too-large")

    def _child_digest(child):
        if not isinstance(child, dict) or not isinstance(child.get("digest"), str):
            raise LayoutError("bad-descriptor")
        return child["digest"]

    def walk_manifest(digest: str, media_type: str, depth: int):
        tick()
        if depth > OCI_MANIFEST_DEPTH_MAX:
            raise LayoutError("manifest-too-deep")
        # Cycle guard: a manifest that references itself (directly or via a
        # chain) is visited at most once.
        if digest in visited:
            return
        visited.add(digest)
        data = _read_blob(layout_dir, digest, cap=OCI_MANIFEST_BYTES_MAX)
        account(digest, data)
        manifests[digest] = media_type or "application/vnd.oci.image.manifest.v1+json"
        doc = json.loads(data)
        # image index / manifest list: recurse into child manifests
        if "manifests" in doc and isinstance(doc["manifests"], list):
            for child in doc["manifests"]:
                walk_manifest(_child_digest(child), child.get("mediaType", ""), depth + 1)
            return
        # image manifest: config + layers
        cfg = doc.get("config") or {}
        if cfg.get("digest"):
            tick()
            account(cfg["digest"], _read_blob(layout_dir, cfg["digest"]))
        for layer in doc.get("layers") or []:
            tick()
            account(_child_digest(layer), _read_blob(layout_dir, layer["digest"]))

    for entry in index.get("manifests") or []:
        digest = _child_digest(entry)
        walk_manifest(digest, entry.get("mediaType", ""), 1)
        ref = (entry.get("annotations") or {}).get("org.opencontainers.image.ref.name")
        if ref:
            names[ref] = digest
    if not manifests:
        raise LayoutError("empty-layout")
    return {"names": names, "manifests": manifests, "blobs": blobs}


def _make_handler(layout_dir: str, model: dict):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "dsmack-oci/1"

        def log_message(self, *_a):  # silence; no request logging (no content leak)
            pass

        def _send_bytes(self, status, body, content_type=None, head_only=False):
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.end_headers()
            if not head_only and body:
                self.wfile.write(body)

        def _route(self, head_only=False):
            path = self.path.split("?", 1)[0]
            if path == "/v2/" or path == "/v2":
                return self._send_bytes(200, b"{}", "application/json", head_only)
            parts = path.strip("/").split("/")
            # /v2/<name...>/manifests/<ref>  or  /v2/<name...>/blobs/<digest>
            if len(parts) >= 4 and parts[0] == "v2" and parts[-2] in ("manifests", "blobs"):
                kind = parts[-2]
                ref = parts[-1]
                name = "/".join(parts[1:-2])
                try:
                    if kind == "manifests":
                        # A digest ref must name a KNOWN manifest; a non-digest
                        # ref is a TAG and must match a known ref name EXACTLY
                        # (no falling back to "any manifest for this name").
                        if _digest_ok(ref):
                            digest = ref if ref in model["manifests"] else None
                        else:
                            digest = model["names"].get(ref)
                        if digest is None or digest not in model["manifests"]:
                            return self._send_bytes(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}',
                                                    "application/json", head_only)
                        body = _read_blob(layout_dir, digest)  # re-verified each serve
                        ct = model["manifests"][digest]
                        self.send_response(200)
                        self.send_header("Content-Type", ct)
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Docker-Content-Digest", digest)
                        self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                        self.end_headers()
                        if not head_only:
                            self.wfile.write(body)
                        return
                    else:  # blobs
                        if ref not in model["blobs"]:
                            return self._send_bytes(404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}',
                                                    "application/json", head_only)
                        body = _read_blob(layout_dir, ref)  # re-verified each serve
                        return self._send_bytes(200, body, "application/octet-stream", head_only)
                except (LayoutError, OSError):
                    return self._send_bytes(500, b'{"errors":[{"code":"INTERNAL"}]}',
                                            "application/json", head_only)
            return self._send_bytes(404, b'{"errors":[{"code":"NOT_FOUND"}]}',
                                    "application/json", head_only)

        def do_GET(self):
            self._route(head_only=False)

        def do_HEAD(self):
            self._route(head_only=True)

        def do_PUT(self):  # read-only registry: uploads are refused
            self._send_bytes(405, b'{"errors":[{"code":"UNSUPPORTED"}]}', "application/json")

        do_POST = do_PUT
        do_DELETE = do_PUT

    return _Handler


def serve(layout_dir: str, host: str, port: int, ready_file: str | None = None,
          server_holder: list | None = None):
    """Verify then serve the layout read-only on (host, port).  Blocks until
    the server is shut down.  Writes ready_file after binding."""
    model = verify_layout(layout_dir)
    handler = _make_handler(layout_dir, model)
    httpd = ThreadingHTTPServer((host, port), handler)
    if server_holder is not None:
        server_holder.append(httpd)
    bound_port = httpd.server_address[1]
    if ready_file:
        with open(ready_file, "w") as handle:
            handle.write("%s:%d\n" % (host, bound_port))
    httpd.serve_forever(poll_interval=0.25)


# -- CLI registration -------------------------------------------------------

def _cmd_oci_verify(args) -> int:
    try:
        model = verify_layout(args.layout)
    except (LayoutError, OSError, ValueError, KeyError) as exc:
        print("DSMACK_OCI_LAYOUT_REFUSED %s" % exc, file=sys.stderr)
        return 2
    print("DSMACK_OCI_LAYOUT_OK names=%d manifests=%d blobs=%d"
          % (len(model["names"]), len(model["manifests"]), len(model["blobs"])))
    for name, digest in sorted(model["names"].items()):
        print("DSMACK_OCI_REF %s %s" % (name, digest))
    return 0


def _cmd_oci_serve(args) -> int:
    try:
        verify_layout(args.layout)  # fail closed before announcing readiness
    except (LayoutError, OSError, ValueError, KeyError) as exc:
        print("DSMACK_OCI_LAYOUT_REFUSED %s" % exc, file=sys.stderr)
        return 2
    holder: list = []

    def _stop_on_signal(*_a):
        if holder:
            threading.Thread(target=holder[0].shutdown, daemon=True).start()

    import signal
    signal.signal(signal.SIGTERM, _stop_on_signal)
    signal.signal(signal.SIGINT, _stop_on_signal)
    serve(args.layout, args.host, args.port, ready_file=args.ready_file, server_holder=holder)
    return 0


def register_subcommands(sub) -> None:
    p = sub.add_parser("oci-verify", help="fully verify an OCI image layout (fail closed)")
    p.add_argument("layout")
    p.set_defaults(func=_cmd_oci_verify)

    p = sub.add_parser("oci-serve", help="serve an OCI layout read-only (loopback, digest-preserving)")
    p.add_argument("layout")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--ready-file", default=None)
    p.set_defaults(func=_cmd_oci_serve)
