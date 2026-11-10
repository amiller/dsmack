"""The oracle canary workload: one service mints a P-256 key K in memory, calls /v1/Attest with
report_data = K's public key x || y, then signs whatever the host asks for under its own domain,
sha256("dsmack.canary.oracle/1" || msg), never a dsmack.canary.claim/1 message. It dials the host
(the Mac's loopback through gvproxy) and answers one JSON line per request until the host hangs up.

python3 workload.py <repo> <image files> <starter public-tree> <out> <variable|constant> <port> [print-k]

variable: pure-Python double-and-add, deliberately variable-time. constant: the image's OpenSSL.
print-k writes K to the outputs, for a test entry whose claim must succeed.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dstack-compat"))
import canary_workload as cw  # noqa: E402

NAME = "oracle-canary-v1"
HOST = "192.168.127.254"
CODE = r'''
import ctypes,hashlib,http.client,json,os,socket
SIGNER,PORT,PRINT_K=%r,%d,%r
DOMAIN,CLAIM=b"dsmack.canary.oracle/1",b"dsmack.canary.claim/1"
P=2**256-2**224+2**192+2**96-1;N=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G=(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
def add(a,b):
    if a is None or b is None:return a or b
    if a[0]==b[0] and (a[1]+b[1])%%P==0:return None
    l=(3*a[0]*a[0]-3)*pow(2*a[1],-1,P) if a==b else (b[1]-a[1])*pow(b[0]-a[0],-1,P)
    x=(l*l-a[0]-b[0])%%P;return x,(l*(a[0]-x)-a[1])%%P
def mul(k,q=G):
    r=None
    while k:
        if k&1:r=add(r,q)
        q,k=add(q,q),k>>1
    return r
rand=lambda:int.from_bytes(os.urandom(32),"big")%%(N-1)+1
if SIGNER=="variable":
    K=rand();pub=b"".join(v.to_bytes(32,"big") for v in mul(K))
    def sign(m):
        e,k=int.from_bytes(hashlib.sha256(DOMAIN+m).digest(),"big"),rand();r=mul(k)[0]%%N
        return r,pow(k,-1,N)*(e+r*K)%%N
else:
    c,V,S=ctypes.CDLL("libcrypto.so.3"),ctypes.c_void_p,ctypes.c_size_t
    c.EVP_PKEY_Q_keygen.restype=c.EVP_MD_CTX_new.restype=c.EVP_sha256.restype=V
    c.EVP_PKEY_get_octet_string_param.argtypes=[V,ctypes.c_char_p,ctypes.c_char_p,S,ctypes.POINTER(S)]
    c.EVP_DigestSignInit.argtypes=[V]*5;c.EVP_DigestSign.argtypes=[V,ctypes.c_char_p,ctypes.POINTER(S),ctypes.c_char_p,S];c.EVP_MD_CTX_free.argtypes=[V]
    pk=V(c.EVP_PKEY_Q_keygen(None,None,b"EC",b"P-256"));b,n=ctypes.create_string_buffer(65),S()
    assert pk.value and c.EVP_PKEY_get_octet_string_param(pk,b"encoded-pub-key",b,65,ctypes.byref(n))==1 and n.value==65;pub=b.raw[1:]
    def sign(m):
        ctx,d,n=c.EVP_MD_CTX_new(),ctypes.create_string_buffer(80),S(80)
        try:assert c.EVP_DigestSignInit(ctx,None,c.EVP_sha256(),None,pk)==1 and c.EVP_DigestSign(ctx,d,ctypes.byref(n),DOMAIN+m,len(DOMAIN)+len(m))==1
        finally:c.EVP_MD_CTX_free(ctx)
        d=d.raw;lr=d[3];return int.from_bytes(d[4:4+lr],"big"),int.from_bytes(d[6+lr:6+lr+d[5+lr]],"big")
class U(http.client.HTTPConnection):
    def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.connect("/var/run/dstack.sock")
u=U("localhost");u.request("POST","/v1/Attest",json.dumps({"report_data":pub.hex()}),{"Content-Type":"application/json"})
r=u.getresponse();att=json.loads(r.read());assert r.status==200,att
out={"signer":SIGNER,"public_key":pub.hex(),"attestation":att["attestation"],**({"K":"%%064x"%%K} if PRINT_K else {})}
open("/workspace/artifacts/oracle.json","w").write(json.dumps(out));print(json.dumps(out),flush=True)
f=socket.create_connection((%r,PORT),timeout=900).makefile("rwb")
f.write(json.dumps(out).encode()+b"\n");f.flush()
for line in f:
    m=bytes.fromhex(json.loads(line)["msg"])
    f.write(json.dumps({"error":"claim message"} if m.startswith(CLAIM) else dict(zip("rs",("%%064x"%%v for v in sign(m))))).encode()+b"\n");f.flush()
'''


def manifest(starter, files, signer, port, print_k):
    m = json.loads(cw.manifest(starter, files))
    svc = json.loads(m["docker_compose_file"])["services"]["attester"]
    del svc["security_profile"]
    svc["command"] = ["-c", CODE % (signer, port, print_k, HOST)]
    m.update(name=NAME, network={"mode": "nat", "listen_ports": [],
                                 "egress": [{"destination": HOST + "/32", "protocol": "tcp", "port": port}]},
             docker_compose_file=json.dumps({"services": {"oracle": svc}}, sort_keys=True, separators=(",", ":")),
             outputs={"artifacts": [{"name": "oracle", "path": "/workspace/artifacts/oracle.json"}],
                      "capture": ["stdout", "stderr"]})
    return cw.canon(m)


if __name__ == "__main__":
    repo, files, starter, out = map(Path, sys.argv[1:5])
    signer, port, print_k = sys.argv[5], int(sys.argv[6]), sys.argv[7:] == ["print-k"]
    assert signer in ("variable", "constant")
    cw.pack(repo, files, starter, out, NAME, manifest(starter, files, signer, port, print_k))
