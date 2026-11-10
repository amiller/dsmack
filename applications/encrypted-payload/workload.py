#!/usr/bin/env python3
"""Pack a digest-pinned encrypted-payload loader with the existing measured guest image."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "dstack-compat"), str(ROOT / "applications/browser-p2p")]
import canary_workload as cw
from public_pack import pack_public

NAME = "encrypted-payload-v1"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "reference", "image", "ciphertext", "out"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--policy", required=True)
    a = p.parse_args()
    layout = a.image / "oci-layout"
    index = json.loads((layout / "index.json").read_bytes())
    digest = index["manifests"][0]["digest"]
    image_manifest = json.loads((layout / "blobs/sha256" / digest.split(":")[1]).read_bytes())
    if "layers" not in image_manifest:
        raise ValueError("export the single arm64 image manifest, not a multi-platform index")
    m = json.loads(a.reference.read_bytes())
    meta = json.loads((a.base / "metadata.json").read_bytes())
    m["base_vm"].update(cmdline=meta["cmdline"], initrd_sha256=cw.fsha(a.base / "initramfs.cpio.gz"),
        kernel_sha256=cw.fsha(a.base / "Image"), metadata_sha256=cw.fsha(a.base / "metadata.json"),
        os_image_hash=cw.fsha(a.base / "sha256sum.txt"), rootfs_sha256=cw.fsha(a.base / "rootfs.squashfs.verity"),
        verity_root_hash=next(t.split("=", 1)[1] for t in meta["cmdline"].split() if t.startswith("dstack.rootfs_hash=")))
    u = urlsplit(a.policy)
    if u.scheme not in ("http", "https"):
        raise ValueError("policy must use HTTP or HTTPS")
    destination = str(ipaddress.ip_network(ipaddress.ip_address(u.hostname)))
    service = {"image": "127.0.0.1:5005/encrypted-loader@" + digest,
        "entrypoint": ["/opt/encrypted/loader.py"],
        "command": [a.task, a.policy, cw.fsha(a.ciphertext)], "read_only": True,
        "volumes": ["artifacts:/workspace/artifacts:rw", "/var/run/dstack.sock:/var/run/dstack.sock:ro",
                    "/run/dsmack:/run/dsmack:rw"]}
    m.update(name=NAME, allowed_files=[],
        runtime_inputs={"env": {"mode": "none"}, "stdin": {"mode": "none"}, "user_config": {"mode": "none"}},
        network={"mode": "nat", "listen_ports": [], "egress": [{"destination": destination, "protocol": "tcp",
                     "port": u.port or (443 if u.scheme == "https" else 80)}]},
        docker_compose_file=cw.canon({"services": {"loader": service}}).decode(),
        harness={"name": "encrypted-loader", "path": "/opt/encrypted/loader.py",
                 "sha256": cw.fsha(Path(__file__).with_name("loader.py")), "version": "encrypted-payload-1"},
        outputs={"artifacts": [{"name": name.removesuffix(".json"), "path": "/workspace/artifacts/" + name}
                               for name in ("attestation.json", "release.json", "answer.json")], "capture": ["stdout", "stderr"]})
    raw = cw.canon(m)
    a.out.mkdir(mode=0o700)
    (a.out / "compose-manifest.json").write_bytes(raw)
    cw.pack(ROOT, a.base, a.image, a.out / "disk", NAME, raw, build_disk=pack_public)


if __name__ == "__main__":
    main()
