"""The signed Swift runner (runner/sign.sh) as sdk/test_sdk.py's runner, for node/tests/sdk_e2e.py --runner-dir. Laptop side.
Each boot is one `open -n -W Runner.app --args run ... --sdk-node ... --attest` on the Mac (App Attest needs a
LaunchServices launch), with its own run directory, base and image store under cfg['runner']['remote']. A booted
runner's host-side dsmack.sock (the socket it relays to the guest's /var/run/dsmack.sock) is forwarded to a local
unix socket, so the same dsmack_sdk Client talks to it. A refused boot exits before creating the socket; its error is
the runner log."""
import json, re, secrets, subprocess, time
from pathlib import Path


class RealRunners:
    def __init__(self, cfg, local):
        self.r, self.local, self.procs = cfg['runner'], Path(local), []

    def ssh(self, cmd, **kw):
        return subprocess.run(['ssh', self.r['host'], cmd], check=True, text=True, capture_output=True, **kw).stdout

    def launch(self, node, compose, allow, variant, attest):
        rd = f"{self.r['remote']}/{re.sub('[^A-Za-z0-9]', '', Path(compose).stem)}-{variant}-{secrets.token_hex(3)}"
        self.ssh(f"mkdir -p {rd}/base && ln -s {self.r['kernel']} {rd}/base/vmlinux-arm64 && cat > {rd}/app-compose.json", input=Path(compose).read_text())
        self.ssh(f'cat > {rd}/allow.json', input=json.dumps(allow))
        app = self.r['apps'][variant]
        p = subprocess.Popen(['ssh', self.r['host'], f'open -n -W --stdout {rd}/runner.stdout --stderr {rd}/runner.log {app} --args run '
                              f'--compose {rd}/app-compose.json --sdk-node {node} --sdk-allow {rd}/allow.json --out {rd}/out --base {rd}/base '
                              f"--oci-archive {self.r['oci']} {'--attest' if attest else '--no-attest'}"])
        self.procs.append(p)
        return rd, p

    def log(self, rd):
        return self.ssh(f'cat {rd}/runner.log').strip()

    def boot(self, node, compose, allow, variant='good', attest=True):
        """(Client socket path, None, rd) once the runner serves dsmack.sock, or (None, runner log, rd) if it exits first."""
        rd, p = self.launch(node, compose, allow, variant, attest)
        while 'up' not in self.ssh(f'test -S {rd}/out/dsmack.sock && echo up || true'):
            if p.poll() is not None:
                return None, self.log(rd), rd
            time.sleep(1)
        sock = self.local / f'{Path(rd).name}.sock'
        self.procs.append(subprocess.Popen(['ssh', '-N', '-o', 'ExitOnForwardFailure=yes', '-L', f'{sock}:{rd}/out/dsmack.sock', self.r['host']]))
        for _ in range(100):
            if sock.exists():
                return sock, None, rd
            time.sleep(0.1)
        raise TimeoutError(f'forward of {rd}/out/dsmack.sock')

    def run_to_exit(self, node, compose, allow, timeout=300):
        """Boots a compose whose guest exits; returns (guest stdout, runner log)."""
        rd, p = self.launch(node, compose, allow, 'good', True)
        p.wait(timeout)
        return self.ssh(f'cat {rd}/out/guest_stdout.txt'), self.log(rd)

    def close(self):
        for p in self.procs:
            p.terminate()
