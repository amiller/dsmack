"""python3 verify.py <dstack-run.json> <dsmack-run.json>: both worker keys reach the same KMS root."""
import json
import sys
import time

from dsmack_dstack import verify_dstack_chain, verify_worker_chain

dstack, mac = (json.loads(open(p).read().strip().splitlines()[-1]) for p in sys.argv[1:3])
b = lambda h: bytes.fromhex(h)
grant = json.loads(mac["key_provider_info"])
roots = set()
for out, dom, alg in ((dstack, "worker-signing", "secp256k1"), (dstack["ed25519"], "worker-ed", "ed25519")):
    roots.add(verify_dstack_chain(b(out["public_key"]), [b(c) for c in out["signature_chain"]], dom, alg, b(dstack["app_id"])))
for out, dom, alg in ((mac, "worker-signing", "secp256k1"), (mac["ed25519"], "worker-ed", "ed25519")):
    roots.add(verify_worker_chain(b(out["public_key"]), [b(c) for c in out["signature_chain"]], dom, alg,
                                  b(grant["app_id"]), grant, int(time.time())))
assert len(roots) == 1, [r.hex() for r in roots]
assert mac["compose_hash"] == grant["compose_hash"]
print(json.dumps({"kms_root": roots.pop().hex(), "dstack_worker_key": dstack["public_key"], "dstack_attest_status": dstack["attest_status"],
                  "mac_worker_key": mac["public_key"], "mac_compose_hash": mac["compose_hash"], "ok": True}))
