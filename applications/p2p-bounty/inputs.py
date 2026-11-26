"""Host-side bounty input and the measured driver config.

pinned(repo, base)  -> {path: sha256} of the base files the check imports, plus ethers.js
request(repo, commit, payee, chain_id, bounty, id, ethers) -> the JSON line the guest driver reads
"""
import base64
import hashlib
import subprocess
from pathlib import Path

CANDIDATE = "applications/relay-broker/workspaces.mjs"
BASE_FILES = ["applications/payments/admission.mjs", "applications/payments/schema.mjs",
              "applications/relay-broker/attestation.mjs", "applications/relay-broker/fleet.mjs",
              "applications/relay-broker/grants.mjs", "applications/relay-broker/inference.mjs",
              "applications/relay-broker/ownership.mjs", "applications/relay-broker/payments.mjs",
              "dstack-compat/binding.mjs", "dstack-compat/secret-release/policy.mjs"]
ETHERS = "ethers.js"  # ethers@6.17.0 dist/ethers.js
DOMAIN = "dsmack.bounty.claim/1"
HERE = Path(__file__).resolve().parent


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def base_files(repo, base, ethers):
    out = {p: git(repo, "show", "%s:%s" % (base, p)) for p in BASE_FILES}
    out[ETHERS] = Path(ethers).read_bytes()
    return out


def pinned(repo, base, ethers):
    return {p: hashlib.sha256(b).hexdigest() for p, b in base_files(repo, base, ethers).items()}


def loose(repo, oid):
    kind = git(repo, "cat-file", "-t", oid).strip()
    body = git(repo, "cat-file", kind.decode(), oid)
    raw = kind + b" " + str(len(body)).encode() + b"\0" + body
    assert hashlib.sha1(raw).hexdigest() == oid
    return raw


def objects(repo, commit):
    """The commit, every tree on the path to CANDIDATE and its blob, as loose objects."""
    ids = [commit, git(repo, "rev-parse", commit + "^{tree}").strip().decode()]
    parts = CANDIDATE.split("/")
    for i in range(len(parts)):
        ids.append(git(repo, "rev-parse", "%s:%s" % (commit, "/".join(parts[:i + 1]))).strip().decode())
    return [loose(repo, oid).hex() for oid in ids]


def request(repo, base, commit, payee, chain_id, bounty, id, ethers):
    commit = git(repo, "rev-parse", commit + "^{commit}").strip().decode()
    return {"chain_id": chain_id, "bounty": bounty, "id": id, "payee": payee, "commit": commit,
            "objects": objects(repo, commit),
            "files": {p: base64.b64encode(b).decode() for p, b in base_files(repo, base, ethers).items()}}
