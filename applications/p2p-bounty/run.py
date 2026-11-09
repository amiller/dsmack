#!/usr/bin/env python3
"""Run the bounty checker on your Mac and keep the guest's result.

python3 run.py <runner dir> <run dir> <request.json>

The runner dir holds DsmackRunner.app, base/ (guest image files), runtime/base/{scratch,result}-template.ext4,
runtime/helper/gvproxy-darwin and enrollment/keyId.txt. The run dir holds workload.img and compose-manifest.json
and receives out/, result.json (with the attestation when the check passed), stdout.txt, stderr.txt and gvproxy.log.
"""
import hashlib
import json
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

d, t, req = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).read_bytes()
b, rt = d / "base", d / "runtime"
compose = json.loads((t / "compose-manifest.json").read_bytes())
port = compose["network"]["egress"][0]["port"]


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()


def fsha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def desc(p):
    return {"path": str(p), "sha256": fsha(p), "bytes": p.stat().st_size}


meta = json.loads((b / "metadata.json").read_bytes())
args = dict(x.split("=", 1) for x in meta["cmdline"].split() if "=" in x)
osh = fsha(b / "sha256sum.txt")


def template(n):
    p = rt / "base" / (n + "-template.ext4")
    return {n + "_template_path": str(p), n + "_template_sha256": args["dstack.%s_template_sha256" % n],
            n + "_template_bytes": p.stat().st_size}


image = canon({"schema": "dsmack-general-launcher/image-manifest/1", "arch": "aarch64", "description": "bounty checker",
               "image_id": osh, "cmdline": meta["cmdline"],
               "guest": {"console": "hvc0", "scratch_device": "vdb", "workload_device": "vdc", "supervisor_markers": "DSMACK_RESULT_CLOSED_V1"},
               "kernel": desc(b / "Image"), "initrd": desc(b / "initramfs.cpio.gz"),
               "system_disk": dict(desc(b / "rootfs.squashfs.verity"), format="raw", verity_root_hash=args["dstack.rootfs_hash"]),
               "resource_profiles": {"mini-4096": {"mem_mib": 4096, "vcpus": 1, "basis": "bounty checker:4096MiB/1vCPU"}},
               "provenance": {"profile_id": "bounty-checker-v1", "release_inventory_sha256": "0" * 64}})
(t / "image-manifest.json").write_bytes(image)
(t / "policy.json").write_bytes(canon({"schema": "dsmack-general-launcher/admission-policy/1", "policy_id": "bounty-checker-4096-1-600",
    "notes": "bounty checker", "admitted_images": [{"image_id": osh, "manifest_sha256": hashlib.sha256(image).hexdigest(), "admitted_by": "local:p2p-bounty"}],
    "resource_limits": {"max_mem_mib": 4096, "max_vcpus": 1, "max_runtime_seconds": 600},
    "device_contract": {"system": "vda", "scratch": "vdb", "workload": "vdc"}}))
(t / "admission.json").write_bytes(canon({"admission_version": 1, "allowed_os_image_hashes": [osh]}))
(t / "challenge.bin").write_bytes(secrets.token_bytes(32))
(t / "session.json").write_bytes(canon({"schema": "dsmack-general-launcher/session/3", "policy_path": str(t / "policy.json"),
    "image_manifest_path": str(t / "image-manifest.json"), "checksum_manifest_path": str(b / "sha256sum.txt"),
    "metadata_path": str(b / "metadata.json"), "admission_path": str(t / "admission.json"),
    "compose_manifest_path": str(t / "compose-manifest.json"), "profile": "mini-4096", "workload_disk_path": str(t / "workload.img"),
    "workload_sha256": fsha(t / "workload.img"), "workload_id": compose["name"], "runtime_seconds": 600,
    "private_input_path": "", "net_socket_path": str(t / "net.sock"), **template("scratch"), **template("result")}))

srv = socket.create_server(("127.0.0.1", port))


def serve():
    conn, _ = srv.accept()
    conn.sendall(req)
    (t / "result.json").write_bytes(conn.makefile("rb").readline())


threading.Thread(target=serve, daemon=True).start()
net = subprocess.Popen([str(rt / "helper/gvproxy-darwin"), "-listen-qemu", "unix://%s" % (t / "net.sock"), "-ssh-port", "-1",
                        "-log-file", str(t / "gvproxy.log")])
while not (t / "net.sock").exists():
    assert net.poll() is None, "gvproxy exited"
    time.sleep(0.1)
try:
    subprocess.run(["/usr/bin/open", "-n", "-W", "--stdout", str(t / "stdout.txt"), "--stderr", str(t / "stderr.txt"),
                    str(d / "DsmackRunner.app"), "--args", "hvf-v3", str(t / "out"), str(t / "session.json"), str(t / "challenge.bin"),
                    str(d / "enrollment/keyId.txt")], check=True, timeout=1320)
finally:
    net.terminate()
    net.wait()
result = json.loads((t / "result.json").read_bytes())
print(json.dumps({k: result.get(k) for k in ("passed", "commit", "payee")}))
