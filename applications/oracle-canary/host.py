"""Host side of an oracle run: accept the guest's connection on 127.0.0.1:<port>, time <n> signing
requests on random messages, then ask for a claim message (it must be refused).

python3 host.py <port> <n> <out dir>   writes hello.json and timing.csv (i,msg,ns,r,s)
"""
import json
import os
import socket
import sys
import time

port, n, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
srv = socket.create_server(("127.0.0.1", port))
conn, _ = srv.accept()
f = conn.makefile("rwb")
open(os.path.join(out, "hello.json"), "wb").write(f.readline())


def ask(msg):
    t = time.perf_counter_ns()
    f.write(json.dumps({"msg": msg.hex()}).encode() + b"\n")
    f.flush()
    reply = json.loads(f.readline())
    return time.perf_counter_ns() - t, reply


with open(os.path.join(out, "timing.csv"), "w") as csv:
    csv.write("i,msg,ns,r,s\n")
    for i in range(n):
        msg = os.urandom(32)
        ns, r = ask(msg)
        csv.write("%d,%s,%d,%s,%s\n" % (i, msg.hex(), ns, r["r"], r["s"]))
_, refused = ask(b"dsmack.canary.claim/1" + os.urandom(84))
open(os.path.join(out, "claim-refusal.json"), "w").write(json.dumps(refused))
assert refused == {"error": "claim message"}, refused
conn.close()
print("oracle answered %d requests and refused the claim message" % n)
