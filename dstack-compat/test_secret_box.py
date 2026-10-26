import json
import os
import pathlib
import subprocess
import tempfile

import pytest

import agent
import guest_attest
import secret_box
from test_guest_attest import call

POLICY = pathlib.Path(__file__).parent / "secret-release/policy.mjs"


def js_seal(pub, secret, task_id):
    """The release policy's seal, run in node."""
    code = ("const p = await import(process.argv[1]); const [pub, s, t] = process.argv.slice(2);"
            "console.log(JSON.stringify(await p.seal(p.unhex(pub), p.unhex(s), t)))")
    out = subprocess.run(["node", "--input-type=module", "-e", code, POLICY.as_uri(), pub.hex(), secret.hex(), task_id],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)


@pytest.fixture
def worker():
    k = 0x1234567890ABCDEF ** 3 % guest_attest.P256_N
    d = tempfile.mkdtemp()
    servers = agent.start(d, ["worker"], secret=k)
    yield os.path.join(d, "worker.sock"), k
    for s in servers:
        s.shutdown()


def test_get_secret_opens_the_policy_seal(worker):
    sock, k = worker
    sealed = js_seal(guest_attest.p256_public(k), b"task secret \x00\xff", "task-7")
    code, out = call(sock, "GetSecret", dict(task_id="task-7", **sealed))
    assert code == 200 and bytes.fromhex(out["secret"]) == b"task secret \x00\xff"


def test_get_secret_refuses_off_curve_epk(worker):
    # An off-curve epk would turn GetSecret into an invalid-curve oracle on the guest's secret-key.
    sock, k = worker
    sealed = js_seal(guest_attest.p256_public(k), b"s", "t")
    code, out = call(sock, "GetSecret", dict(sealed, task_id="t", epk=sealed["epk"][:-2] + "00"))
    assert code == 400 and "not a P-256 point" in out["error"]
