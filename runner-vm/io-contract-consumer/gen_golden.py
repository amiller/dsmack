#!/usr/bin/env python3
"""Golden-vector GENERATOR (producer side) for the v3 run-result composition.

SWIFT04 repair2. This script plays the PRODUCER: it emits the exact bytes the
Swift launcher (app-src/Sources/mar/RunResultEnvelopeV3.swift + V3Launch.swift)
must write, using the SAME canonicalization the io-contract-reference verifier
uses (contract10 canonical_bytes / sha256_obj, imported read-only through the
frozen pins). The companion consumer.py plays the VERIFIER and re-derives every
digest from the reference rules. Both are committed under vectors/ so producer
and verifier agree on identical golden bytes — the "independent producer/verifier
golden vectors" the review required.

Deterministic: no time, no randomness. Re-running reproduces byte-identical
vectors (checked in CI via `python3 gen_golden.py --check`).
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REF = "/data/amiller/dsmack/attested-runner-20261020/io-contract-reference/candidate"
if REF not in sys.path:
    sys.path.insert(0, REF)

from runresult_ref import protocol, statement as S            # noqa: E402
from runresult_ref.frozen import (                            # noqa: E402
    canonical_bytes, sha256_obj, execution_evidence_digest)

VECTORS = os.path.join(HERE, "vectors")

# ---- fixed inputs (a contract-valid synthetic launch; NOT hardware evidence) ----
CHALLENGE = "golden-challenge-0001"
KEY_ID_B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz"   # 32 bytes b64, <=60 chars
LAUNCH_COUNTER = 1
RESULT_COUNTER = 2
TEMPLATE_BYTES = 2 * 1024 * 1024                              # 2 MiB vdd template
RESULT_BYTES = TEMPLATE_BYTES                                  # == template (R06 fixed size)

# The exact compose-manifest bytes the producer retains as compose-manifest.bin;
# M = sha256(these bytes) is the "manifest" the reference re-hashes (statement.py:80).
MANIFEST_BYTES = canonical_bytes({
    "schema": "dsmack-app-compose/1",
    "name": "golden-demo",
    "services": {"app": {"image": "demo@sha256:" + "11" * 32}},
})
M = hashlib.sha256(MANIFEST_BYTES).hexdigest()

# base_vm carries EXACTLY the ten SHARED_BASE_VM_FIELDS (compare_shared_facts).
BASE_VM = {
    "architecture": "arm64",
    "cmdline": "console=hvc0 rdinit=/init panic=-1",
    "initrd_sha256": "aa" * 32,
    "kernel_sha256": "bb" * 32,
    "memory_mb": 2048,
    "metadata_sha256": "cc" * 32,
    "os_image_hash": "dd" * 32,
    "rootfs_sha256": "ee" * 32,
    "vcpus": 1,
    "verity_root_hash": "ff" * 32,
}
# base_vm_launch.admission carries EXACTLY the four SHARED_ADMISSION_FIELDS, plus
# an independent boot observation namespace the verifier never compares.
BASE_VM_LAUNCH = {
    "admission": {
        "decision": "admit",
        "os_image_hash": "dd" * 32,
        "admission_sha256": "99" * 32,
        "admission_version": "contract10",
    },
    "boot": {"observed_by": "launcher", "ok": True},
}
OBSERVED = {"runtime_seconds": 60, "profile": "demo-1x2g"}

# The authenticated receipt-evidence body N (EVIDENCE_BODY_KEYS). L is its /4
# evidence digest, exactly as the launch assertion and the verifier compute it.
RECEIPT_EVIDENCE_BODY = {
    "attestation": None,
    "base_vm": BASE_VM,
    "base_vm_launch": BASE_VM_LAUNCH,
    "harness_sha256": None,
    "manifest_sha256": M,
    "observed": OBSERVED,
    "outputs": None,
    "run_id": None,
    "runtime_inputs_commitment": None,
}
L = execution_evidence_digest(RECEIPT_EVIDENCE_BODY)


def compose_envelope(result_sha256, console_sha256, console_bytes, truncated):
    """The producer's envelope body (RunResultEnvelopeV3.composeRunResultEnvelope).
    Exact ENVELOPE_KEYS; status 'halted'; result_disk.role 'vdd'; console
    limit_bytes == MAX_CONSOLE_BYTES; lifecycle vmm_code 0 / backend_abi 3."""
    return {
        "schema": protocol.ENVELOPE_SCHEMA,
        "launch": {
            "evidence_sha256": L,
            "manifest_sha256": M,
            "challenge": CHALLENGE,
            "key_id_b64": KEY_ID_B64,
            "counter": LAUNCH_COUNTER,
        },
        "result_disk": {
            "role": "vdd",
            "template_sha256": "77" * 32,
            "template_bytes": TEMPLATE_BYTES,
            "sha256": result_sha256,
            "bytes": RESULT_BYTES,
        },
        "console": {
            "sha256": console_sha256,
            "bytes": console_bytes,
            "truncated": truncated,
            "limit_bytes": protocol.MAX_CONSOLE_BYTES,
        },
        "runtime_input": {"present": False, "max_bytes": 0, "commitment_claim": None},
        "lifecycle": {"vmm_code": 0, "run_ms": 1234, "backend_abi": 3},
        "status": "halted",
    }


def nul_join(*parts):
    return b"\x00".join(p.encode() if isinstance(p, str) else p for p in parts)


def build_statement(launch_cd, result_cd, E):
    """The producer's v3 statement (V3Launch.swift). Exactly the reference
    STATEMENT_KEYS plus the extra `result_assertion` member and the v3 schema
    value — the two differences the consumer adapter normalizes."""
    return {
        "schema": "dsmack-general-launcher/v3-run-statement/1",
        "challenge": CHALLENGE,
        "key_id": KEY_ID_B64,
        "assertion": {
            "assertion_domain": protocol.LAUNCH_ASSERTION_DOMAIN,
            "evidence_domain": protocol.EVIDENCE_DOMAIN,
            "manifest_sha256": M,
            "evidence_sha256": L,
            "client_data_sha256": hashlib.sha256(launch_cd).hexdigest(),
            "receipt_evidence_body": RECEIPT_EVIDENCE_BODY,
        },
        "result_assertion": {
            "result_assertion_domain": protocol.RESULT_ASSERTION_DOMAIN,
            "envelope_domain": protocol.ENVELOPE_DOMAIN,
            "envelope_schema": protocol.ENVELOPE_SCHEMA,
            "launch_evidence_sha256": L,
            "envelope_sha256": E,
            "result_client_data_sha256": hashlib.sha256(result_cd).hexdigest(),
        },
        "identity": {"compose_manifest_sha256": M, "os_image_hash": "dd" * 32,
                     "spec_sha256": "ab" * 32},
        "consumed": OBSERVED,
        "workload": {"sha256": "cd" * 32, "bytes": 65536, "workload_id": "golden"},
        "resources": {"ram_mib": 2048, "vcpus": 1, "runtime_bound_seconds": 60},
        "staging": {"method": "golden", "arch": "arm64"},
        "lifecycle": {"backend_abi": 3, "run_ms": 1234, "vmm_code": 0},
        "output": {"result_sha256": "12" * 32, "console_sha256": "34" * 32},
        "contract10_receipt_fragment": {"base_vm": BASE_VM, "base_vm_launch": BASE_VM_LAUNCH},
        "honesty": {"note": "golden"},
        "trace": {"head": "golden", "events": []},
    }


def build_case(name, result_sha256, console_sha256, console_bytes, truncated):
    env = compose_envelope(result_sha256, console_sha256, console_bytes, truncated)
    env_bytes = canonical_bytes(env)                       # the RETAINED envelope.json
    E = sha256_obj([protocol.ENVELOPE_DOMAIN, env])        # statement.envelope_digest
    # The two assertion preimages, byte-for-byte the reference helpers.
    launch_cd = S.launch_client_data(M, L, CHALLENGE)
    result_cd = S.result_client_data(L, E, CHALLENGE)
    # Cross-check against an inline NUL-join (must match the reference helper).
    assert result_cd == nul_join(protocol.RESULT_ASSERTION_DOMAIN, L, E, CHALLENGE)
    assert launch_cd == nul_join(protocol.LAUNCH_ASSERTION_DOMAIN, M, L, CHALLENGE)
    stmt = build_statement(launch_cd, result_cd, E)
    return {
        "_statement": stmt,
        "_statement_bytes": canonical_bytes(stmt),
        "name": name,
        "_backend_run_result": {
            "schema": "dsmack-backend-v3/run-result/1",
            "result_disk": env["result_disk"],
            "console": env["console"],
            "runtime_input": env["runtime_input"],
            "lifecycle": env["lifecycle"],
        },
        "inputs": {
            "manifest_bytes_b64": None,          # see manifest.bin
            "manifest_sha256_M": M,
            "launch_evidence_body": RECEIPT_EVIDENCE_BODY,
            "launch_evidence_sha256_L": L,
            "challenge": CHALLENGE,
            "key_id_b64": KEY_ID_B64,
            "launch_counter": LAUNCH_COUNTER,
            "result_counter": RESULT_COUNTER,
            "result_template_sha256": env["result_disk"]["template_sha256"],
            "result_template_bytes": env["result_disk"]["template_bytes"],
            "expected_vmm_code": env["lifecycle"]["vmm_code"],
            "private_present": env["runtime_input"]["present"],
        },
        "envelope": env,
        "expected": {
            "envelope_canonical_sha256": hashlib.sha256(env_bytes).hexdigest(),
            "envelope_digest_E": E,                                  # domain-separated
            "launch_client_data_sha256": hashlib.sha256(launch_cd).hexdigest(),
            "result_client_data_sha256": hashlib.sha256(result_cd).hexdigest(),
            "result_client_data_hex": result_cd.hex(),
            "launch_client_data_hex": launch_cd.hex(),
        },
        "_env_bytes": env_bytes,
    }


CASES = [
    build_case("halted_console_complete",
               result_sha256="12" * 32, console_sha256="34" * 32,
               console_bytes=4096, truncated=False),
    build_case("halted_console_truncated",
               result_sha256="56" * 32, console_sha256="78" * 32,
               console_bytes=protocol.MAX_CONSOLE_BYTES, truncated=True),
]


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def generate():
    os.makedirs(VECTORS, exist_ok=True)
    _write(os.path.join(VECTORS, "manifest.bin"), MANIFEST_BYTES)
    index = {"schema": "dsmack-general-launcher/golden-vectors/1",
             "manifest_file": "manifest.bin", "cases": []}
    for c in CASES:
        _write(os.path.join(VECTORS, "envelope.%s.json" % c["name"]), c["_env_bytes"])
        _write(os.path.join(VECTORS, "statement.%s.json" % c["name"]), c["_statement_bytes"])
        # The backend run-result (dsmack-backend-v3/run-result/1) the REAL Swift
        # parseRunResultV3 consumes — fed to the Swift golden harness so it
        # exercises the production compose path, not a reconstruction.
        _write(os.path.join(VECTORS, "backend-run-result.%s.json" % c["name"]),
               canonical_bytes(c["_backend_run_result"]))
        rec = {k: c[k] for k in ("name", "inputs", "envelope", "expected")}
        _write(os.path.join(VECTORS, "case.%s.json" % c["name"]),
               (json.dumps(rec, indent=2, sort_keys=True) + "\n").encode())
        index["cases"].append(c["name"])
    _write(os.path.join(VECTORS, "INDEX.json"),
           (json.dumps(index, indent=2, sort_keys=True) + "\n").encode())
    return index


def check():
    """Regenerate in memory and compare to committed bytes (no writes)."""
    ok = True
    for c in CASES:
        for fn, want in (("envelope.%s.json" % c["name"], c["_env_bytes"]),
                         ("statement.%s.json" % c["name"], c["_statement_bytes"])):
            p = os.path.join(VECTORS, fn)
            if not os.path.exists(p) or open(p, "rb").read() != want:
                print("MISMATCH", fn); ok = False
    return ok


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(0 if check() else 1)
    idx = generate()
    print("generated golden vectors:", idx["cases"])
    print("M =", M)
    print("L =", L)
