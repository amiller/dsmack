#!/usr/bin/env python3
"""Pack the attested egress relay as one v0.2 guest service.

workload.py <repo> <base files> <canary manifest> <arm64 binary> <relay> <task> <policy url> <out>
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

NAME = "egress-relay-v1"
PATH = "/usr/local/bin/dsmack-egress"
SERVE_S = 420


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def manifest(starter, binary, digest, relay, task, policy_url):
    m = json.loads(starter.read_bytes())
    service = {
        "image": "127.0.0.1:5005/dsmack-egress@" + digest,
        "entrypoint": [PATH],
        "command": ["serve", relay, str(SERVE_S), task, policy_url],
        "read_only": True,
        "volumes": ["artifacts:/workspace/artifacts:rw", "/var/run/dstack.sock:/var/run/dstack.sock:ro"],
    }
    m.update(
        name=NAME,
        network={"mode": "nat", "listen_ports": []},
        harness={"name": "egress-relay", "path": PATH,
                 "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "version": "egress-relay-1"},
        docker_compose_file=canon({"services": {"peer": service}}).decode(),
        outputs={"artifacts": [{"name": name, "path": "/workspace/artifacts/" + name}
                               for name in ("attestation", "peer-id")], "capture": ["stdout", "stderr"]},
    )
    return canon(m)


def main():
    repo, files, starter, binary = map(Path, sys.argv[1:5])
    relay, task, policy_url, output = sys.argv[5:9]
    out = Path(output)
    spec = importlib.util.spec_from_file_location("peer_workload", repo / "applications/libp2p-attest/workload.py")
    peer_workload = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(peer_workload)
    sys.path.insert(0, str(repo / "dstack-compat"))
    import canary_workload
    out.mkdir(mode=0o700)
    image = out / "image"
    digest = peer_workload.oci_layout(binary, image, path=PATH, image_name="dsmack-egress")
    mb = manifest(starter, binary, digest, relay, task, policy_url)
    (out / "compose-manifest.json").write_bytes(mb)
    canary_workload.pack(repo, files, image, out / "disk", NAME, mb)


if __name__ == "__main__":
    main()
