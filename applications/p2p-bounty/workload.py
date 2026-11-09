#!/usr/bin/env python3
"""The #98 bounty checker workload: official node:24.15.0-bookworm-slim (arm64) running driver.mjs, with
egress only to the Mac host's input port. Everyone builds the same manifest; claimants download workload.img.

python3 workload.py <repo> <base commit> <ethers.js> <base image files> <out>

Prints manifest_sha256, os_image_hash and the workload disk digest; out/ holds compose-manifest.json and workload.img.
"""
import base64
import gzip
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

import inputs

NAME = "bounty-98-v1"
NODE = "library/node"
NODE_DIGEST = "sha256:682f301a9e8e5731d4bb1889182a2186fe65a312cc81ae86cea6038ef8b1603f"  # 24.15.0-bookworm-slim linux/arm64/v8
HOST, PORT = "192.168.127.254", 18807
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fsha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def b64(p):
    """Compose rejects '$' anywhere, so the measured driver source travels base64-encoded."""
    return base64.b64encode(p.read_bytes()).decode()


def fetch_node(out):
    """Copy the arm64 node image from Docker Hub into out/oci-layout, checking every digest. Returns node's sha256."""
    token = json.load(urllib.request.urlopen(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull" % NODE))["token"]

    def get(kind, digest, accept=""):
        r = urllib.request.Request("https://registry-1.docker.io/v2/%s/%s/%s" % (NODE, kind, digest),
                                   headers={"Authorization": "Bearer " + token, "Accept": accept})
        raw = urllib.request.urlopen(r).read()
        assert "sha256:" + hashlib.sha256(raw).hexdigest() == digest, digest
        (blobs / digest[7:]).write_bytes(raw)
        return raw

    blobs = out / "oci-layout/blobs/sha256"
    blobs.mkdir(parents=True)
    raw = get("manifests", NODE_DIGEST, OCI_MANIFEST)
    m = json.loads(raw)
    assert m["mediaType"] == OCI_MANIFEST
    get("blobs", m["config"]["digest"])
    node = None
    for layer in m["layers"]:
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(get("blobs", layer["digest"])))) as t:
            for e in t:
                if e.name.lstrip("./") == "usr/local/bin/node" and e.isfile():
                    node = hashlib.sha256(t.extractfile(e).read()).hexdigest()
    (out / "oci-layout/index.json").write_bytes(canon({"schemaVersion": 2, "manifests": [
        {"mediaType": OCI_MANIFEST, "digest": NODE_DIGEST, "size": len(raw),
         "platform": {"architecture": "arm64", "os": "linux"}, "annotations": {"org.opencontainers.image.ref.name": "node"}}]}))
    (out / "oci-layout/oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return node


def manifest(files, node_sha256, pinned):
    meta = json.loads((files / "metadata.json").read_bytes())
    root = [t.split("=", 1)[1] for t in meta["cmdline"].split() if t.startswith("dstack.rootfs_hash=")][0]
    here = Path(__file__).resolve().parent
    bounty = {"HOST": HOST, "PORT": PORT, "CANDIDATE": inputs.CANDIDATE, "PINNED": pinned,
              "CHECK": (here / "check-98.mjs").read_text(), "DOMAIN": inputs.DOMAIN}
    checker = {"image": "127.0.0.1:5005/node@" + NODE_DIGEST, "entrypoint": ["/usr/local/bin/node"],
               "command": ["--input-type=module", "-e", 'await import("data:text/javascript;base64,%s")' % b64(here / "driver.mjs")],
               "environment": {"BOUNTY": base64.b64encode(canon(bounty)).decode()}, "read_only": True,
               "volumes": ["state:/workspace/state:rw", "artifacts:/workspace/artifacts:rw",
                           "/var/run/dstack.sock:/var/run/dstack.sock:ro"]}
    return canon({
        "manifest_version": 4, "name": NAME, "allowed_envs": [], "allowed_files": [],
        "base_vm": {"architecture": "aarch64", "cmdline": meta["cmdline"], "memory_mb": 4096, "vcpus": 1,
                    "initrd_sha256": fsha(files / "initramfs.cpio.gz"), "kernel_sha256": fsha(files / "Image"),
                    "metadata_sha256": fsha(files / "metadata.json"), "os_image_hash": fsha(files / "sha256sum.txt"),
                    "rootfs_sha256": fsha(files / "rootfs.squashfs.verity"), "verity_root_hash": root},
        "docker_compose_file": canon({"services": {"checker": checker}}).decode(),
        "harness": {"name": "node", "path": "/usr/local/bin/node", "sha256": node_sha256, "version": "node-24.15.0"},
        "image_platform": {"architecture": "arm64", "os": "linux"},
        "limits": {"output_max_bytes": 1 << 24, "timeout_s": 600, "workspace_max_bytes": 1 << 28},
        "required_envs": [],
        "runner": {"compose_tool": {"name": "docker-compose", "version": "2.26.1-4"}, "container_runtime": "runc",
                   "kind": "oci-compose", "runtime_closure": {"components": [{"name": "runc", "path": "/usr/bin/runc",
                   "registration_args": [], "sha256": "6a8bd8a019e7b10a8d30a9fa85656f795d5957ab7269e5579f438a065b753332"}]},
                   "runtime_name": "runc", "runtime_version": "1.1.15+ds1"},
        "runtime_inputs": {"env": {"mode": "inject"}, "stdin": {"max_bytes": 0, "mode": "none"},
                           "user_config": {"max_bytes": 0, "mode": "none"}},
        "network": {"mode": "nat", "listen_ports": [], "egress": [{"destination": HOST + "/32", "protocol": "tcp", "port": PORT}]},
        "outputs": {"artifacts": [{"name": "result", "path": "/workspace/artifacts/result.json"}], "capture": ["stdout", "stderr"],
                    "completion_service": "checker"}})


if __name__ == "__main__":
    repo, base, ethers, files, out = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5])
    sys.path.insert(0, str(Path(repo) / "dstack-compat"))
    import canary_workload
    starter = out.parent / (out.name + "-image")
    mb = manifest(files, fetch_node(starter), inputs.pinned(repo, base, ethers))
    canary_workload.pack(Path(repo), files, starter, out, NAME, mb)
    (out / "compose-manifest.json").write_bytes(mb)
