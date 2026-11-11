"""A workload that attests once with report_data = Badge.reportData(to) and writes the attestation to its outputs.

python3 workload.py <repo> <image files> <starter public-tree> <out> <report_data hex>

Same inputs as dstack-compat/canary_workload.py; no network. Prints manifest_sha256, os_image_hash, workload digest.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dstack-compat"))
import canary_workload as cw  # noqa: E402

NAME = "badge-claim-v1"
CODE = r'''
import http.client,json,socket
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX);self.sock.connect("/var/run/dstack.sock")
c=C("localhost");c.request("POST","/v1/Attest",json.dumps({"report_data":%r}),{"Content-Type":"application/json"})
r=c.getresponse();out=json.loads(r.read())
assert r.status==200,out
open("/workspace/artifacts/attestation.json","w").write(json.dumps(out))
'''


def manifest(starter, files, report_data):
    m = json.loads(cw.manifest(starter, files))
    c = json.loads(m["docker_compose_file"])
    c["services"]["attester"]["command"] = ["-c", CODE % report_data]
    m.update(name=NAME, network={"mode": "none", "listen_ports": []}, docker_compose_file=json.dumps(c, sort_keys=True, separators=(",", ":")))
    return cw.canon(m)


if __name__ == "__main__":
    repo, files, starter, out = map(Path, sys.argv[1:5])
    cw.pack(repo, files, starter, out, NAME, manifest(starter, files, sys.argv[5]))
