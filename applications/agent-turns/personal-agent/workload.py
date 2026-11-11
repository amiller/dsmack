#!/usr/bin/env python3
"""The personal-agent turn workload: guest/agent_turn.py in its image, one compose service on nat.

python3 workload.py <repo> <base image files> <canary-v1.app-compose.json> <image dir> <task id> <policy url> \
    <state url> <TurnHeads address> <chain id> <out>

<image dir> holds oci-layout/, guest/Dockerfile built as an OCI layout. The manifest is the same for every turn of an agent, so
one secret-release task (id, manifest, image) covers the agent. Prints manifest_sha256, os_image_hash and the
workload disk digest; out/ holds compose-manifest.json and disk/workload.img.
"""
import gzip
import hashlib
import io
import json
import sys
import tarfile
import urllib.parse
from pathlib import Path

NAME = "personal-agent-turn-v1"
PYTHON = "/usr/bin/python3.12"


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def image_file(layout, path):
    """sha256 of path in the image's top layer that has it, and the image manifest digest."""
    blob = lambda d: (layout / "blobs/sha256" / d.removeprefix("sha256:")).read_bytes()
    top = json.loads((layout / "index.json").read_bytes())["manifests"][0]["digest"]
    found = None
    for layer in json.loads(blob(top))["layers"]:
        with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(blob(layer["digest"])))) as tar:
            m = next((m for m in tar if m.name.lstrip("./") == path.lstrip("/")), None)
            if m is not None:
                assert m.isreg(), f"{path} is not a regular file in the image"
                found = hashlib.sha256(tar.extractfile(m).read()).hexdigest()
    assert found, f"{path} is not in the image"
    return found, top


def manifest(canary, layout, task, policy, state, heads, chain_id):
    m = json.loads(canary.read_bytes())
    python, digest = image_file(layout, PYTHON)
    service = {"image": "127.0.0.1:5005/personal-agent-turn@" + digest, "entrypoint": [PYTHON, "-B", "/opt/turn/agent_turn.py"],
               "read_only": True,
               "environment": {"TASK": task, "POLICY": policy, "STATE": state, "HEADS": heads, "CHAIN_ID": chain_id},
               "volumes": ["artifacts:/workspace/artifacts:rw", "/var/run/dstack.sock:/var/run/dstack.sock:ro"]}
    hosts = [urllib.parse.urlsplit(u) for u in (policy, state)]
    egress = [{"destination": u.hostname + "/32", "protocol": "tcp", "port": u.port} for u in hosts]
    m.update(name=NAME, network={"mode": "nat", "listen_ports": [], "egress": egress},
             harness={"name": "python-application", "path": PYTHON, "sha256": python, "version": "personal-agent-turn-1"},
             docker_compose_file=canon({"services": {"turn": service}}).decode(),
             outputs={"artifacts": [{"name": n, "path": "/workspace/artifacts/" + n} for n in ("state", "commit")],
                      "capture": ["stdout", "stderr"]})
    return canon(m)


if __name__ == "__main__":
    repo, files, canary, image = map(Path, sys.argv[1:5])
    out = Path(sys.argv[10])
    sys.path.insert(0, str(repo / "dstack-compat"))
    import canary_workload
    out.mkdir(mode=0o700)
    mb = manifest(canary, image / "oci-layout", *sys.argv[5:10])
    (out / "compose-manifest.json").write_bytes(mb)
    canary_workload.pack(repo, files, image, out / "disk", NAME, mb)
