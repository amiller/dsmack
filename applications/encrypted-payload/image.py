#!/usr/bin/env python3
"""Export the public loader as a single-platform OCI layout without a registry."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main(image, out):
    layout = out / "oci-layout"
    blobs = layout / "blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(raw, media):
        digest = hashlib.sha256(raw).hexdigest()
        (blobs / digest).write_bytes(raw)
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(raw)}

    with tempfile.TemporaryDirectory() as tmp:
        saved = Path(tmp) / "image.tar"
        subprocess.run(["docker", "save", "--output", str(saved), image], check=True)
        with tarfile.open(saved) as tar:
            entry = json.load(tar.extractfile("manifest.json"))[0]
            config = blob(tar.extractfile(entry["Config"]).read(), "application/vnd.oci.image.config.v1+json")
            layers = [blob(gzip.compress(tar.extractfile(name).read(), mtime=0),
                           "application/vnd.oci.image.layer.v1.tar+gzip") for name in entry["Layers"]]
    manifest = blob(canon({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": config, "layers": layers}), "application/vnd.oci.image.manifest.v1+json")
    (layout / "index.json").write_bytes(canon({"schemaVersion": 2, "manifests": [dict(manifest,
        platform={"architecture": "arm64", "os": "linux"}, annotations={"org.opencontainers.image.ref.name": "encrypted-loader"})]}))
    (layout / "oci-layout").write_bytes(canon({"imageLayoutVersion": "1.0.0"}))
    print(manifest["digest"])


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
