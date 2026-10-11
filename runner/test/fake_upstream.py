"""DEV-ONLY fake LLM upstream for the metering test: HTTPS on 127.0.0.1:PORT under a fresh test CA (DIR/ca.der,
for runner --dev-test-anchor). Answers 401 unless the runner injected FAKE_KEY. Usage it reports:
POST /v1/messages (Anthropic) input 25 + output 40; POST /v1/chat/completions (OpenAI) total_tokens 150;
"model": "no-usage" omits usage; "model": "sse" streams with usage in the last chunk. usage: FAKE_KEY=... fake_upstream.py DIR PORT"""
import datetime, json, os, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

d, port, KEY = Path(sys.argv[1]), int(sys.argv[2]), os.environ['FAKE_KEY']
d.mkdir(parents=True)
now = datetime.datetime.now(datetime.timezone.utc)
def cert(cn, key, issuer, issuer_key, *exts):
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1)))
    for e in exts:
        b = b.add_extension(e, critical=False)
    return b.sign(issuer_key, hashes.SHA256())
ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
ca = cert('runner DEV-ONLY test anchor', ca_key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'runner DEV-ONLY test anchor')]), ca_key,
          x509.BasicConstraints(ca=True, path_length=0))
leaf = cert('localhost', leaf_key, ca.subject, ca_key, x509.BasicConstraints(ca=False, path_length=None),
            x509.SubjectAlternativeName([x509.DNSName('localhost')]), x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]))
(d / 'ca.der').write_bytes(ca.public_bytes(serialization.Encoding.DER))
(d / 'leaf.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
(d / 'leaf-key.pem').write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        if self.path == '/v1/messages':
            ok, usage = self.headers['x-api-key'] == KEY, {'input_tokens': 25, 'output_tokens': 40}
        elif self.path == '/v1/chat/completions':
            ok, usage = self.headers['authorization'] == f'Bearer {KEY}', {'prompt_tokens': 50, 'completion_tokens': 100, 'total_tokens': 150}
        else:
            ok, usage = False, None
        if ok and req['model'] == 'sse':  # OpenAI stream with include_usage: usage only in the last chunk (empty choices)
            chunks = [{'choices': [{'delta': {'content': 'hi'}}]}, {'choices': [], 'usage': usage}]
            body = ''.join(f'data: {json.dumps(c)}\n\n' for c in chunks).encode() + b'data: [DONE]\n\n'
            self.send_response(200); self.send_header('content-type', 'text/event-stream')
            self.send_header('content-length', str(len(body))); self.end_headers(); self.wfile.write(body); return
        out = {'model': req['model'], **({'usage': usage} if req['model'] != 'no-usage' else {})} if ok else {'error': 'bad key or path'}
        body = json.dumps(out).encode()
        self.send_response(200 if ok else 401)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = ThreadingHTTPServer(('127.0.0.1', port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(str(d / 'leaf.pem'), str(d / 'leaf-key.pem'))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(f'fake upstream: https://localhost:{port}, anchor {d / "ca.der"}', file=sys.stderr)
srv.serve_forever()
