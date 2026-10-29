#!/usr/bin/env python3
"""The guest peer workload: a scratch image holding the arm64 dsmack-peer, and one compose service that
reserves a slot on the relay, binds its PeerId with /v1/Attest and serves for a while.

python3 workload.py <repo> <base image files> <canary-v1.app-compose.json> <dsmack-peer-arm64> <relay maddr> <out> [ca-bundle]

The optional PEM CA bundle enables WSS certificate validation in the scratch image.

Prints manifest_sha256, os_image_hash and the workload disk digest; out/ holds the manifest and workload.img.
"""
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

NAME = "libp2p-peer-v1"
PATH = "/usr/local/bin/dsmack-peer"
SERVE_S = 420


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def oci_layout(binary, out, path=PATH, image_name="dsmack-peer", ca_cert=None):
    """A one-layer arm64 image with the binary at path; returns its manifest digest."""
    blobs = out / "oci-layout/blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(raw):
        d = hashlib.sha256(raw).hexdigest()
        (blobs / d).write_bytes(raw)
        return {"digest": "sha256:" + d, "size": len(raw)}
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for d in ("usr", "usr/local", "usr/local/bin"):
            info = tarfile.TarInfo(d)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(info)
        if ca_cert is not None:
            for d in ("etc", "etc/ssl", "etc/ssl/certs"):
                info = tarfile.TarInfo(d)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            raw_ca = ca_cert.read_bytes()
            info = tarfile.TarInfo("etc/ssl/certs/ca-certificates.crt")
            info.size, info.mode = len(raw_ca), 0o644
            tar.addfile(info, io.BytesIO(raw_ca))
        raw = binary.read_bytes()
        info = tarfile.TarInfo(path.lstrip("/"))
        info.size, info.mode = len(raw), 0o755
        tar.addfile(info, io.BytesIO(raw))
    tar_raw = layer.getvalue()
    config = blob(canon({"architecture": "arm64", "os": "linux", "config": {"Entrypoint": [path]},
                         "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(tar_raw).hexdigest()]}}))
    gz = blob(gzip.compress(tar_raw, mtime=0))
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", **gz}]}
    top = blob(canon(manifest))
    (out / "oci-layout/index.json").write_bytes(canon({"schemaVersion": 2, "manifests": [
        {"mediaType": manifest["mediaType"], **top, "platform": {"architecture": "arm64", "os": "linux"},
         "annotations": {"org.opencontainers.image.ref.name": image_name}}]}))
    (out / "oci-layout/oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return top["digest"]


def manifest(canary, binary, digest, relay):
    m = json.loads(canary.read_bytes())
    service = {"image": "127.0.0.1:5005/dsmack-peer@" + digest, "entrypoint": [PATH],
               "command": ["serve", relay, str(SERVE_S)], "read_only": True,
               "volumes": ["artifacts:/workspace/artifacts:rw", "/var/run/dstack.sock:/var/run/dstack.sock:ro"]}
    m.update(name=NAME, network={"mode": "nat", "listen_ports": []},
             harness={"name": "libp2p-peer", "path": PATH, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "version": "libp2p-attest-1"},
             docker_compose_file=canon({"services": {"peer": service}}).decode(),
             outputs={"artifacts": [{"name": n, "path": "/workspace/artifacts/" + n} for n in ("attestation", "peer-id")],
                      "capture": ["stdout", "stderr"]})
    return canon(m)


if __name__ == "__main__":
    repo, files, canary, binary = map(Path, sys.argv[1:5])
    relay, out = sys.argv[5], Path(sys.argv[6])
    sys.path.insert(0, str(repo / "dstack-compat"))
    import canary_workload
    out.mkdir(mode=0o700)
    image = out / "image"
    mb = manifest(canary, binary, oci_layout(binary, image, ca_cert=Path(sys.argv[7]) if len(sys.argv) == 8 else None), relay)
    (out / "compose-manifest.json").write_bytes(mb)
    canary_workload.pack(repo, files, image, out / "disk", NAME, mb)
