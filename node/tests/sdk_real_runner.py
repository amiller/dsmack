"""The signed Swift runner (runner/sign.sh) as sdk/test_sdk.py's runner, for node/tests/sdk_e2e.py --runner-dir. Laptop side.
Each boot is one `open -n -W Runner.app --args run ... --sdk-node ... --attest` on the Mac (App Attest needs a
LaunchServices launch), with its own run directory, base and image store under cfg['runner']['remote'].

The runner's /var/run/dsmack.sock exists only inside the VM, so the test reaches it the way any app could export its
own socket: the test compose's guest runs BRIDGE, which opens runner CONNECT tunnels (egress.tcp) to 127.0.0.1:<bridge
port> on the Mac, forwarded here, each led by sha256 of the runner's boot clientData (from runner.local/attest). This
side reads the same clientData.bin from the run directory, so every tunnel reaches the boot it came from, and serves a
local unix socket per boot: each client connection takes one tunnel, and the guest pipes it to /var/run/dsmack.sock.
A refused boot exits before the VM starts; its error is the runner log."""
import hashlib, json, queue, re, secrets, socket, subprocess, threading, time
from pathlib import Path

BRIDGE = r'''
import base64, hashlib, json, socket, sys, threading
PORT = int(sys.argv[1])
def egress():
    s = socket.socket(socket.AF_UNIX); s.connect('/run/egress.sock'); return s
def head(s):
    h = b''
    while not h.endswith(b'\r\n\r\n'):
        c = s.recv(1)
        if not c: raise SystemExit('egress closed')
        h += c
    return h
s = egress(); body = b'{"data":"dsmack-sdk-test-bridge"}'
s.sendall(b'POST /attest HTTP/1.1\r\nHost: runner.local\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
h = head(s); n = int(next(l.split(b':')[1] for l in h.split(b'\r\n') if l.lower().startswith(b'content-length')))
r = b''
while len(r) < n: r += s.recv(n - len(r))
boot = hashlib.sha256(base64.b64decode(json.loads(r)['bootClientData'])).hexdigest().encode()
def pipe(a, b):
    try:
        while d := a.recv(65536): b.sendall(d)
    except OSError: pass
    for x in (a, b):
        try: x.shutdown(socket.SHUT_RDWR)
        except OSError: pass
print('bridge for boot', boot.decode(), flush=True)
while True:
    t = egress(); t.sendall(b'CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n' % (PORT, PORT))
    assert b' 200 ' in head(t).split(b'\r\n')[0]
    t.sendall(boot + b'\n')
    first = t.recv(65536)
    if not first: t.close(); continue
    u = socket.socket(socket.AF_UNIX); u.connect('/var/run/dsmack.sock'); u.sendall(first)
    threading.Thread(target=pipe, args=(t, u)).start(); threading.Thread(target=pipe, args=(u, t)).start()
'''


def bridge_compose(port):
    """The test compose's guest command and egress: BRIDGE, tunnelling only to the forwarded bridge port."""
    return ['python', '-c', BRIDGE, str(port)], [{'host': '127.0.0.1', 'port': port}]


def pipe(a, b):
    try:
        while d := a.recv(65536):
            b.sendall(d)
    except OSError:
        pass
    for x in (a, b):
        try:
            x.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class RealRunners:
    def __init__(self, cfg, local):
        self.r, self.local, self.procs = cfg['runner'], Path(local), []
        self.tunnels, self.lock, self.rd_of = {}, threading.Lock(), {}
        self.listener = socket.create_server(('127.0.0.1', self.r['bridge_port']))
        threading.Thread(target=self.accept, daemon=True).start()

    def queue(self, boot):
        with self.lock:
            return self.tunnels.setdefault(boot, queue.Queue())

    def accept(self):
        while True:
            t, _ = self.listener.accept()
            boot = b''
            while not boot.endswith(b'\n'):
                c = t.recv(1)
                if not c:
                    break
                boot += c
            self.queue(boot.strip().decode()).put(t)

    def serve(self, sock, boot):
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(sock))
        server.listen()

        def loop():
            while True:
                c, _ = server.accept()
                t = self.queue(boot).get(timeout=60)
                threading.Thread(target=pipe, args=(c, t), daemon=True).start()
                threading.Thread(target=pipe, args=(t, c), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()

    def ssh(self, cmd, **kw):
        return subprocess.run(['ssh', self.r['host'], cmd], check=True, text=True, capture_output=True, **kw).stdout

    def launch(self, node, compose, variant, attest):
        rd = f"{self.r['remote']}/{re.sub('[^A-Za-z0-9]', '', Path(compose).stem)}-{variant}-{secrets.token_hex(3)}"
        self.ssh(f"mkdir -p {rd}/base && ln -s {self.r['kernel']} {rd}/base/vmlinux-arm64 && cat > {rd}/app-compose.json", input=Path(compose).read_text())
        app = self.r['apps'][variant]
        p = subprocess.Popen(['ssh', self.r['host'], f'open -n -W --stdout {rd}/runner.stdout --stderr {rd}/runner.log {app} --args run '
                              f'--compose {rd}/app-compose.json --sdk-node {node} --out {rd}/out --base {rd}/base '
                              f"--oci-archive {self.r['oci']} {'--attest' if attest else '--no-attest'}"])
        self.procs.append(p)
        return rd, p

    def log(self, rd):
        return self.ssh(f'cat {rd}/runner.log').strip()

    def boot(self, node, compose, variant='good', attest=True):
        """(local socket path, None, rd) once the guest's bridge has a tunnel up, or (None, runner log, rd) if the runner exits first."""
        rd, p = self.launch(node, compose, variant, attest)
        boot, deadline = None, time.time() + 300
        while True:
            if p.poll() is not None:
                return None, self.log(rd), rd
            if boot is None:
                boot = self.ssh(f'test -f {rd}/out/clientData.bin && shasum -a 256 {rd}/out/clientData.bin | cut -c1-64 || true').strip() or None
            if boot and not self.queue(boot).empty():
                break
            assert time.time() < deadline, f'no bridge tunnel from {rd}: {self.log(rd)}'
            time.sleep(1)
        sock = self.local / f'{Path(rd).name}.sock'
        self.serve(sock, boot)
        self.rd_of[str(sock)] = rd
        return sock, None, rd

    def host_sockets(self, rd):
        """Every socket file in the run directory, and the unix sockets the runner process holds as lsof names them."""
        pid = self.ssh(f"pgrep -f -- '--out {rd}/out' | head -1").strip()
        return {'socket_files': self.ssh(f'find {rd} -type s').split(), 'runner_pid': pid,
                'runner_unix_sockets': self.ssh(f'lsof -a -p {pid} -U -F n | grep ^n || true').split()}

    def run_to_exit(self, node, compose, timeout=300):
        """Boots a compose whose guest exits; returns (guest stdout, runner log)."""
        rd, p = self.launch(node, compose, 'good', True)
        p.wait(timeout)
        return self.ssh(f'cat {rd}/out/guest_stdout.txt'), self.log(rd)

    def close(self):
        for p in self.procs:
            p.terminate()
        self.listener.close()
