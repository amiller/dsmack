"""Prepare an own three-certificate synthetic chain; no Apple names/OIDs/trust changes."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
if root.exists():
    raise SystemExit("recipient directory must be fresh")
os.umask(0o077)
root.mkdir(mode=0o700)
script_dir = Path(__file__).resolve().parent

def run(name, args):
    with (root / (name + ".log")).open("x") as log:
        status = subprocess.call([sys.executable, str(script_dir / "bounded.py"), "30"] + args, stdout=log, stderr=subprocess.STDOUT)
    print(name + "_status=" + str(status), flush=True)
    if status:
        raise SystemExit(status)

for kind in ["root", "intermediate", "leaf"]:
    run(kind + "_key", ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(root / (kind + ".pem"))])
    run(kind + "_csr", ["openssl", "req", "-new", "-key", str(root / (kind + ".pem")), "-out", str(root / (kind + ".csr")), "-subj", "/CN=dsmack-synthetic-" + kind])
for kind, ca, ca_key, serial, extensions in [
    ("root", None, "root", "101", "basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n"),
    ("intermediate", "root", "root", "102", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"),
    ("leaf", "intermediate", "intermediate", "103", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment,keyAgreement\n"),
]:
    ext = root / (kind + ".ext")
    ext.write_text(extensions)
    args = ["openssl", "x509", "-req", "-in", str(root / (kind + ".csr")), "-days", "1", "-set_serial", serial, "-extfile", str(ext), "-out", str(root / (kind + "-cert.pem"))]
    if ca is None:
        args += ["-signkey", str(root / (ca_key + ".pem"))]
    else:
        args += ["-CA", str(root / (ca + "-cert.pem")), "-CAkey", str(root / (ca_key + ".pem"))]
    run(kind + "_cert", args)
    run(kind + "_der", ["openssl", "x509", "-in", str(root / (kind + "-cert.pem")), "-outform", "DER", "-out", str(root / (kind + ".der"))])
run("verify", ["openssl", "verify", "-CAfile", str(root / "root-cert.pem"), "-untrusted", str(root / "intermediate-cert.pem"), str(root / "leaf-cert.pem")])
with (root / "chain.der").open("xb") as stream:
    for kind in ["leaf", "intermediate", "root"]:
        data = (root / (kind + ".der")).read_bytes()
        assert stream.write(data) == len(data)
run("leaf_sec1", ["openssl", "ec", "-in", str(root / "leaf.pem"), "-outform", "DER", "-out", str(root / "leaf.sec1.der")])
run("leaf_x963", [sys.executable, str(script_dir / "recipient_x963.py"), str(root / "leaf.sec1.der"), str(root / "leaf.x963")])
