"""A workload that obtains a task secret: /v1/Attest binding the request, POST to the release policy,
/v1/GetSecret on the ciphertext. Writes the attestation and sha256 of the secret to its outputs.

python3 secret_workload.py <repo> <image files> <starter public-tree> <out> <task id> <policy host:port>

Same inputs as canary_workload.py; network nat so the service reaches the policy (on the Mac's loopback
the guest sees it as gvproxy's 192.168.127.254). Prints manifest_sha256, os_image_hash, workload digest.
"""
import json
import sys
from pathlib import Path

import canary_workload as cw

NAME = "secret-release-v1"
CODE = r'''
import hashlib,http.client,json,socket,sys
TASK,HOST,PORT=%r,%r,%d
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX);self.sock.connect("/var/run/dstack.sock")
def post(c,path,body):
    c.request("POST",path,json.dumps(body),{"Content-Type":"application/json"});r=c.getresponse();out=json.loads(r.read())
    assert r.status==200,(path,r.status,out);return out
rd=hashlib.sha256(b"dsmack.secret-request/1"+TASK.encode()).digest()+bytes(32)
att=post(C("localhost"),"/v1/Attest",{"report_data":rd.hex()})["attestation"]
out={"task_id":TASK,"attestation":att}
open("/workspace/artifacts/secret-release.json","w").write(json.dumps(out))
sealed=post(http.client.HTTPConnection(HOST,PORT,timeout=60),"/release",{"task_id":TASK,"attestation":att})
secret=bytes.fromhex(post(C("localhost"),"/v1/GetSecret",dict(task_id=TASK,**sealed))["secret"])
out.update(sealed=sealed,secret_sha256=hashlib.sha256(secret).hexdigest())
open("/workspace/artifacts/secret-release.json","w").write(json.dumps(out))
print(json.dumps(out))
'''


def manifest(starter, files, task, host, port):
    m = json.loads(cw.manifest(starter, files))
    svc = json.loads(m["docker_compose_file"])["services"]["attester"]
    del svc["security_profile"]
    svc["command"] = ["-c", CODE % (task, host, port)]
    m.update(name=NAME, network={"mode": "nat", "listen_ports": []},
             docker_compose_file=json.dumps({"services": {"worker": svc}}, sort_keys=True, separators=(",", ":")),
             outputs={"artifacts": [{"name": "secret-release", "path": "/workspace/artifacts/secret-release.json"}],
                      "capture": ["stdout", "stderr"]})
    return cw.canon(m)


if __name__ == "__main__":
    repo, files, starter, out = map(Path, sys.argv[1:5])
    host, port = sys.argv[6].rsplit(":", 1)
    mb = manifest(starter, files, sys.argv[5], host, int(port))
    cw.pack(repo, files, starter, out, NAME, mb)
