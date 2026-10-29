"""The canary workload: one service that calls /v1/Attest once with zero report_data,
writes the attestation to its outputs (the claim material) and sleeps out the run.
Its manifest sha256 is what Owner canary entries bind.

python3 canary_workload.py <repo> <image files> <starter public-tree> <out>

<image files> is a derived base image (Image, initramfs.cpio.gz, rootfs.squashfs.verity,
metadata.json, sha256sum.txt); the starter tree supplies the python OCI image.
Prints manifest_sha256, os_image_hash and the workload disk digest.
"""
import hashlib
import json
import secrets
import shutil
import sys
from pathlib import Path

NAME = "canary-v1"
SLEEP_S = 480
CODE = r'''
import http.client,json,socket,time
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX);self.sock.connect("/var/run/dstack.sock")
c=C("localhost");c.request("POST","/v1/Attest",json.dumps({"report_data":"00"*64}),{"Content-Type":"application/json"})
r=c.getresponse();out=json.loads(r.read())
assert r.status==200,out
open("/workspace/artifacts/attestation.json","w").write(json.dumps(out))
time.sleep(%d)
''' % SLEEP_S


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fsha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def manifest(starter, files):
    m = json.loads((starter / "manifests/bounty-board-search-primary-review-v1.app-compose.json").read_bytes())
    image = json.loads(m["docker_compose_file"])["services"]["primary"]["image"]
    meta = json.loads((files / "metadata.json").read_bytes())
    root = [t.split("=", 1)[1] for t in meta["cmdline"].split() if t.startswith("dstack.rootfs_hash=")][0]
    m.update(name=NAME, allowed_files=[],
             base_vm=dict(m["base_vm"], cmdline=meta["cmdline"], initrd_sha256=fsha(files / "initramfs.cpio.gz"),
                          kernel_sha256=fsha(files / "Image"), metadata_sha256=fsha(files / "metadata.json"),
                          os_image_hash=fsha(files / "sha256sum.txt"), rootfs_sha256=fsha(files / "rootfs.squashfs.verity"),
                          verity_root_hash=root),
             docker_compose_file=json.dumps({"services": {"attester": {
                 "image": image, "entrypoint": ["/usr/bin/python3", "-I", "-B"], "command": ["-c", CODE],
                 "read_only": True, "security_profile": "browser-sandbox-v1",
                 "volumes": ["state:/workspace/state:rw", "artifacts:/workspace/artifacts:rw",
                             "/var/run/dstack.sock:/var/run/dstack.sock:ro"]}}}, sort_keys=True, separators=(",", ":")),
             outputs={"artifacts": [{"name": "attestation", "path": "/workspace/artifacts/attestation.json"}],
                      "capture": ["stdout", "stderr"]})
    return canon(m)


def main(repo, files, starter, out):
    pack(repo, files, starter, out, NAME, manifest(starter, files))


def pack(repo, files, starter, out, name, mb, build_disk=None):
    """Validate manifest bytes mb and pack them with the image and the starter's OCI layout into out/workload.img."""
    sys.path[:0] = [str(repo / "applications/pilot-client/workload"),
                    str(repo / "base-vm/browser-sandbox-v1/source/runner-content/lib")]
    from transport_loader import load
    from dsmack_compose_contract.manifest import validate_manifest_bytes
    validate_manifest_bytes(mb)
    osh = fsha(files / "sha256sum.txt")
    out.mkdir(mode=0o700)
    tree = out / "public-tree"
    for n in ("manifests", "admission", "base-bundle", "closure-context"):
        (tree / n).mkdir(parents=True)
    (tree / "manifests" / (name + ".app-compose.json")).write_bytes(mb)
    for n in ("Image", "initramfs.cpio.gz", "rootfs.squashfs.verity", "metadata.json", "sha256sum.txt"):
        shutil.copyfile(files / n, tree / "base-bundle" / n)
    (tree / "admission/base-admission.json").write_bytes(canon({"admission_version": 1, "allowed_os_image_hashes": [osh]}))
    (tree / "closure-context/context.json").write_bytes(canon({"schema": "dsmack-result-closure-context/1",
                                                              "attempt_id": secrets.token_hex(16), "selectors": [name]}))
    (tree / "WORKLOAD").write_text(name + "\n")
    shutil.copytree(starter / "oci-layout", tree / "oci-layout")
    if build_disk is None:
        t = load(repo / "base-vm/browser-sandbox-v1/source/smoke/launch_vm_dstack_arm64.py")
        t.start_overall_deadline(300)
        t.build_workload_disk(None, str(tree), str(out / "workload.img"), 1 << 30)
    else:
        build_disk(tree, out / "workload.img", name, hashlib.sha256(mb).hexdigest())
    print(json.dumps({"manifest_sha256": hashlib.sha256(mb).hexdigest(), "os_image_hash": osh,
                      "workload_sha256": fsha(out / "workload.img")}))


if __name__ == "__main__":
    main(*map(Path, sys.argv[1:]))
