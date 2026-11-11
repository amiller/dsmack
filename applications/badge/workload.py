"""The badge workload: measures the CPU class from inside the guest, reads {to, badge, chainid} from the host,
attests with report_data = Badge.reportData(to, chip) and writes {attestation, to, chip} to its outputs.

python3 workload.py <repo> <image files> <starter public-tree> <out>    build the disk; prints manifest_sha256
python3 workload.py serve <badge> <chainid> <to>                        answer the guest once, on the Mac

The manifest has no per-claim value in it, so one Badge pins it. The guest reaches the host at
192.168.127.254:PORT through gvproxy. CPU class from the guest's feature flags (Hypervisor.framework hides the
part number): sme2 -> M4+, bf16 -> M2-M3, else M1.
"""
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dstack-compat"))
import canary_workload as cw  # noqa: E402

NAME = "badge-claim-v2"
PORT = 18979
CODE = r'''
import hashlib,http.client,json,socket
lines=open("/proc/cpuinfo").read().splitlines()
field=lambda k:next(l for l in lines if l.startswith(k)).split(":",1)[1]
assert field("CPU implementer").strip()=="0x61",field("CPU implementer")
feat=set(field("Features").split())
chip="M4+" if "sme2" in feat else "M2-M3" if "bf16" in feat else "M1"
req=json.loads(socket.create_connection(("192.168.127.254",%d),timeout=120).makefile().readline())
rd=hashlib.sha256(b"dsmack.badge.claim/2"+int(req["chainid"]).to_bytes(32,"big")+bytes.fromhex(req["badge"][2:])
  +bytes.fromhex(req["to"][2:])+chip.encode().ljust(32,b"\0")).digest()+bytes(32)
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX);self.sock.connect("/var/run/dstack.sock")
c=C("localhost");c.request("POST","/v1/Attest",json.dumps({"report_data":rd.hex()}),{"Content-Type":"application/json"})
r=c.getresponse();out=json.loads(r.read())
assert r.status==200,out
open("/workspace/artifacts/attestation.json","w").write(json.dumps(dict(out,to=req["to"],chip=chip)))
''' % PORT


def manifest(starter, files):
    m = json.loads(cw.manifest(starter, files))
    c = json.loads(m["docker_compose_file"])
    svc = c["services"]["attester"]
    del svc["security_profile"]
    svc["command"] = ["-c", CODE]
    egress = [{"destination": "192.168.127.254/32", "protocol": "tcp", "port": PORT}]
    m.update(name=NAME, network={"mode": "nat", "listen_ports": [], "egress": egress},
             docker_compose_file=json.dumps(c, sort_keys=True, separators=(",", ":")))
    return cw.canon(m)


def serve(badge, chainid, to):
    with socket.create_server(("127.0.0.1", PORT)) as s:
        conn, _ = s.accept()
        conn.sendall(json.dumps({"badge": badge, "chainid": chainid, "to": to}).encode() + b"\n")
        conn.close()


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(*sys.argv[2:5])
    else:
        repo, files, starter, out = map(Path, sys.argv[1:5])
        cw.pack(repo, files, starter, out, NAME, manifest(starter, files))
