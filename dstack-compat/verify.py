"""python3 verify.py <dstack-run.json> <dsmack-run.json>: both worker keys reach the same KMS root."""
import json
import sys
import time

from dsmack_dstack import verify_dstack_chain, verify_worker_chain

dstack, mac = (json.loads(open(p).read().strip().splitlines()[-1]) for p in sys.argv[1:3])
b = lambda h: bytes.fromhex(h)
args = ("worker-signing", "secp256k1")
kms_a = verify_dstack_chain(b(dstack["public_key"]), [b(c) for c in dstack["signature_chain"]], *args, b(dstack["app_id"]))
grant = json.loads(mac["key_provider_info"])["dsmack_worker_grant"]
kms_b = verify_worker_chain(b(mac["public_key"]), [b(c) for c in mac["signature_chain"]], *args,
                            b(grant["app_id"]), grant, int(time.time()))
assert kms_a == kms_b, (kms_a.hex(), kms_b.hex())
assert mac["compose_hash"] == grant["compose_hash"]
print(json.dumps({"kms_root": kms_a.hex(), "dstack_worker_key": dstack["public_key"],
                  "mac_worker_key": mac["public_key"], "mac_compose_hash": mac["compose_hash"], "ok": True}))
