"""The TLS canary workload (#170): service `tls` mints a P-256 key K in memory, calls /v1/Attest
with report_data = K's public key x || y, then sends K as the x-api-key of a request to
https://api.anthropic.com every 30 s, through the host's CONNECT proxy as the credential
sentinel does. Anthropic answers 401 and drops it. Reading K means reading the guest's
provider TLS, and K signs claimDigest for the Oracle entry that pins this manifest.

python3 tls.py <repo> <image files> <starter public-tree> <out> <system|sentinel> <port> [seconds]

system: the image's /etc/ssl/certs/ca-certificates.crt, as the sentinel was launched before #170.
sentinel: guest/sentinel/roots/api.anthropic.com.pem, embedded in the measured manifest.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dstack-compat"))
import canary_workload as cw  # noqa: E402

HOST = "192.168.127.254"
SENTINEL_ROOTS = ROOT / "base-vm/browser-sandbox-v1/source/guest/sentinel/roots/api.anthropic.com.pem"
CODE = r'''
import ctypes,http.client,json,socket,ssl,time
ROOTS,PROXY,PORT,SECONDS,SOCK,OUT=%r,%r,%d,%d,%r,%r
c,V,S=ctypes.CDLL("libcrypto.so.3"),ctypes.c_void_p,ctypes.c_size_t
c.EVP_PKEY_Q_keygen.restype=V
c.EVP_PKEY_get_octet_string_param.argtypes=[V,ctypes.c_char_p,ctypes.c_char_p,S,ctypes.POINTER(S)]
c.EVP_PKEY_get_bn_param.argtypes=[V,ctypes.c_char_p,ctypes.POINTER(V)];c.BN_bn2binpad.argtypes=[V,ctypes.c_char_p,ctypes.c_int]
pk,b,n,bn,k=V(c.EVP_PKEY_Q_keygen(None,None,b"EC",b"P-256")),ctypes.create_string_buffer(65),S(),V(),ctypes.create_string_buffer(32)
assert pk.value and c.EVP_PKEY_get_octet_string_param(pk,b"encoded-pub-key",b,65,ctypes.byref(n))==1 and n.value==65
assert c.EVP_PKEY_get_bn_param(pk,b"priv",ctypes.byref(bn))==1 and c.BN_bn2binpad(bn,k,32)==32
pub,K=b.raw[1:],k.raw.hex()
class U(http.client.HTTPConnection):
    def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.connect(SOCK)
u=U("localhost");u.request("POST","/v1/Attest",json.dumps({"report_data":pub.hex()}),{"Content-Type":"application/json"})
r=u.getresponse();att=json.loads(r.read());assert r.status==200,att
out={"public_key":pub.hex(),"attestation":att["attestation"]}
open(OUT,"w").write(json.dumps(out));print(json.dumps(out),flush=True)
ctx=ssl.create_default_context(cafile=ROOTS) if ROOTS.startswith("/") else ssl.create_default_context(cadata=ROOTS)
body=json.dumps({"model":"claude-haiku-5-5","max_tokens":1,"messages":[{"role":"user","content":"canary"}]})
end=time.time()+SECONDS
while True:
    try:
        conn=http.client.HTTPSConnection(PROXY,PORT,timeout=30,context=ctx);conn.set_tunnel("api.anthropic.com",443)
        conn.request("POST","/v1/messages",body,{"x-api-key":"sk-ant-canary-"+K,"anthropic-version":"2023-06-01","content-type":"application/json"})
        print("provider",conn.getresponse().status,flush=True);conn.close()
    except (OSError,ssl.SSLError) as e:print("provider",type(e).__name__,flush=True)
    if time.time()>=end:break
    time.sleep(30)
'''


def code(roots, port, seconds, sock="/var/run/dstack.sock", proxy=HOST, out="/workspace/artifacts/oracle.json"):
    return CODE % (roots, proxy, port, seconds, sock, out)


def manifest(starter, files, variant, port, seconds):
    roots = {"system": "/etc/ssl/certs/ca-certificates.crt", "sentinel": SENTINEL_ROOTS.read_text()}[variant]
    m = json.loads(cw.manifest(starter, files))
    svc = json.loads(m["docker_compose_file"])["services"]["attester"]
    del svc["security_profile"]
    svc["entrypoint"][0] = m["harness"]["path"]
    svc["command"] = ["-c", code(roots, port, seconds)]
    m.update(name="tls-canary-v1-" + variant, network={"mode": "nat", "listen_ports": [],
             "egress": [{"destination": HOST + "/32", "protocol": "tcp", "port": port}]},
             docker_compose_file=json.dumps({"services": {"tls": svc}}, sort_keys=True, separators=(",", ":")),
             outputs={"artifacts": [{"name": "oracle", "path": "/workspace/artifacts/oracle.json"}],
                      "capture": ["stdout", "stderr"]})
    return cw.canon(m)


if __name__ == "__main__":
    repo, files, starter, out = map(Path, sys.argv[1:5])
    variant, port, seconds = sys.argv[5], int(sys.argv[6]), int(sys.argv[7]) if len(sys.argv) > 7 else 600
    cw.pack(repo, files, starter, out, "tls-canary-v1-" + variant, manifest(starter, files, variant, port, seconds))
