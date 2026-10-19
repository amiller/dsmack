"""Write the test app-compose files with dstack's own Python SDK serializer (to_deterministic_json),
and record the SDK's get_compose_hash so the runner's sha256(file bytes) can be compared to it.
Run on the laptop: python3 test/gen_compose.py
"""
import importlib.util, json
from pathlib import Path

SDK = Path.home() / 'projects/dstack/dstack/sdk/python/src/dstack_sdk/get_compose_hash.py'
spec = importlib.util.spec_from_file_location('gch', SDK)
gch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gch)
HERE = Path(__file__).parent

IMAGE = 'docker.io/curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69'  # 8.11.1, alpine-based
GUEST = r'''
p() { curl -sS --unix-socket /run/egress.sock -w '\n[status=%{http_code}]\n' "$@"; }
echo "== attest"; p -X POST -d '{"data":"abalone-attest/1|peerA|peerB|n1"}' http://runner.local/attest
echo "== key_a"; p -X POST -d '{"path":"peer-id"}' http://runner.local/key
echo "== key_a2"; p -X POST -d '{"path":"peer-id"}' http://runner.local/key
echo "== key_b"; p -X POST -d '{"path":"other"}' http://runner.local/key
echo "== net"; ls /sys/class/net; ip addr
echo "== direct_ip"; curl -sS -m 5 -o /dev/null https://1.1.1.1/; echo "exit=$?"
echo "== direct_dns"; curl -sS -m 5 -o /dev/null https://httpbin.org/get; echo "exit=$?"
echo "== allowed"; p -H 'Authorization: Bearer GUEST-SECRET' -H 'x-api-key: guest-xkey' http://httpbin.org/anything/allowed | tee /home/curl_user/upstream.json
echo "== xkey"; p http://httpbin.org/anything/xkey
echo "== not_allowlisted_host"; p http://example.org/
echo "== wrong_method"; p -X DELETE http://httpbin.org/anything/allowed
echo "== wrong_path"; p http://httpbin.org/get
echo "== dot_segments"; p --path-as-is http://httpbin.org/anything/../get
echo "== metered_no_usage"; p -X POST -H 'content-type: application/json' -d '{"model":"m","max_tokens":100}' http://httpbin.org/anything/v1/messages
echo "== metered_over_budget"; p -X POST -H 'content-type: application/json' -d '{"model":"m","max_tokens":5000}' http://httpbin.org/anything/v1/messages
echo "== metered_no_max_tokens"; p -X POST -H 'content-type: application/json' -d '{"model":"m"}' http://httpbin.org/anything/v1/messages
echo "== redirect_not_followed"; p 'http://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.org%2F&status_code=302'
echo "== pin_fail"; p http://example.com/
echo "== keepalive"; curl -sv --unix-socket /run/egress.sock -X POST -H 'content-type: application/json' -d '{"path":"ka"}' -w '\n[status=%{http_code}]\n' http://runner.local/key http://runner.local/key 2>&1 | grep -E 'status=|Re-?using'
echo "== request_cap"; for i in 1 2 3 4 5 6; do p http://httpbin.org/anything/n$i | tail -1; done
sync
'''
# DEV-ONLY metering boot against test/fake_upstream.py on localhost:8443 (runner --dev-test-anchor). Budget 1000:
# 1000 - 65 - 150 - 100 (no usage: reservation kept) = 685, so max_tokens 685 passes only if earlier reservations
# were settled to usage; after it 685 - 65 = 620 remain and 621 is refused.
METER = r'''
q() { curl -sS --unix-socket /run/egress.sock -w '\n[status=%{http_code}]\n' -X POST -H 'content-type: application/json' "$@"; }
echo "== anthropic"; q -d '{"model":"m","max_tokens":100}' http://localhost:8443/v1/messages
echo "== openai"; q -d '{"model":"m","max_tokens":200}' http://localhost:8443/v1/chat/completions
echo "== no_usage"; q -d '{"model":"no-usage","max_tokens":100}' http://localhost:8443/v1/messages
echo "== settled"; q -d '{"model":"m","max_tokens":685}' http://localhost:8443/v1/messages
echo "== exhausted"; q -d '{"model":"m","max_tokens":621}' http://localhost:8443/v1/messages
echo "== sse"; q -d '{"model":"sse","max_tokens":200,"stream":true}' http://localhost:8443/v1/chat/completions
'''
# DEV-ONLY abalone-interface boot: provider quotes (real RedPill/Phala ACI endpoints), the
# /provider-quote endpoint. 127.0.0.1:8794 is a host HTTP server (test/run_tests.sh); 127.0.0.1:8795 replays a
# recorded RedPill report (stale nonce); localhost:8443 is test/fake_upstream.py, which logs every request it gets.
ABALONE = r'''
p() { curl -sS --unix-socket /run/egress.sock -w '\n[status=%{http_code}]\n' "$@"; }
echo "== quote_before_fetch"; p 'http://runner.local/provider-quote?host=api.redpill.ai'
echo "== redpill"; p http://api.redpill.ai/v1/models | tail -c 200
echo "== redpill_quote_bytes"; curl -sS --unix-socket /run/egress.sock 'http://runner.local/provider-quote?host=api.redpill.ai' | sha256sum
echo "== large_body_repeat"; for i in $(seq 20); do curl -sS -H 'connection: close' --unix-socket /run/egress.sock 'http://runner.local/provider-quote?host=api.redpill.ai' | sha256sum; done | sort | uniq -c
echo "== redpill_again"; p http://api.redpill.ai/v1/models | tail -1
echo "== wrong_compose"; p http://tee.redpill.ai/v1/models
echo "== wrong_compose_quote"; p 'http://runner.local/provider-quote?host=tee.redpill.ai'
echo "== replayed"; p http://localhost:8443/v1/replayed
echo "== spki_mismatch"; p http://openrouter.phala.com/v1/models
echo "== nearai_bad_key"; p http://cloud-api.near.ai/v1/models
'''
REDPILL_COMPOSE = '0637b3d506c80c0328c84697c290f5fb7eef811c8d022124e04ee9b0f5f99567'  # private-ai-gateway, measured 2026-10-08
KEY = r'''
for path in peer-id other; do echo "== $path"; curl -sS --unix-socket /run/egress.sock -X POST -d "{\"path\":\"$path\"}" http://runner.local/key; echo; done
'''
# Signed pass only (runner --reenroll-seconds 5): two /attest calls straddling a re-enrollment.
REENROLL = r'''
a() { curl -sS --unix-socket /run/egress.sock -X POST -d "{\"data\":\"abalone-attest/1|peerA|peerB|$1\"}" http://runner.local/attest; echo; }
echo "== attest_1"; a r1
sleep 12
echo "== attest_2"; a r2
'''
# CONNECT tunnels from the abalone peer image's node (curl's --unix-socket ignores -x/-p, so curl cannot test them).
# 127.0.0.1:8794 is a host HTTP server (test/run_tests.sh), the only egress.tcp entry.
TUNNEL = r'''
const net = require("net");
const tunnel = (target, after) => new Promise((done) => {
  const s = net.connect("/run/egress.sock"); let buf = Buffer.alloc(0), open = false;
  s.on("connect", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
  s.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    const end = buf.indexOf("\r\n\r\n");
    if (!open && end >= 0) { console.log("connect: " + buf.subarray(0, buf.indexOf("\r\n"))); open = true; buf = buf.subarray(end + 4); if (after) s.write(after); }
  });
  s.on("close", () => { console.log(buf.toString()); done(); });
});
(async () => {
  console.log("== tunnel_ok"); await tunnel("127.0.0.1:8794", "GET /tunnel.txt HTTP/1.0\r\n\r\n");
  console.log("== tunnel_refused_port"); await tunnel("127.0.0.1:8796");
  console.log("== tunnel_refused_host"); await tunnel("httpbin.org:80");
})();
'''
PEER_IMAGE = 'local/abalone-peer@sha256:4de0c4901691cf65f1ea168f726ca8a85385a3b389adc7fcf5c8ae242ce16738'


bearer = {'auth_header': 'Authorization', 'auth_prefix': 'Bearer '}


def compose(image, name='runner-test'):
    dc = {'services': {'app': {'image': image, 'command': ['/bin/sh', '-c', GUEST]}}}
    egress = {'max_requests': 9, 'max_tokens': 1000, 'allow': [
        {'host': 'httpbin.org', 'method': 'GET', 'path_prefix': '/anything/xkey', 'auth_header': 'x-api-key'},
        {'host': 'httpbin.org', 'method': 'GET', 'path_prefix': '/anything/', **bearer},
        {'host': 'httpbin.org', 'method': 'POST', 'path_prefix': '/anything/v1/messages', 'auth_header': 'x-api-key', 'metered': True},
        {'host': 'httpbin.org', 'method': 'GET', 'path_prefix': '/redirect-to', **bearer},
        {'host': 'example.com', 'method': 'GET', 'path_prefix': '/'},
    ]}
    return gch.AppCompose(runner='docker-compose', manifest_version=2, name=name, kms_enabled=True,
                          docker_compose_file=json.dumps(dc), egress=egress)


main = compose(IMAGE)
text = gch.to_deterministic_json(main)
(HERE / 'app-compose.json').write_text(text)
(HERE / 'app-compose.sdk-hash').write_text(gch.get_compose_hash(main) + '\n')
(HERE / 'app-compose-byte.json').write_bytes(text.encode().replace(b'runner-test', b'runner-tesT'))
(HERE / 'app-compose-tag.json').write_text(gch.to_deterministic_json(compose('docker.io/curlimages/curl:8.11.1')))
meter = {'max_requests': 8, 'max_tokens': 1000, 'allow': [
    {'host': 'localhost:8443', 'method': 'POST', 'path_prefix': '/v1/messages', 'auth_header': 'x-api-key', 'metered': True},
    {'host': 'localhost:8443', 'method': 'POST', 'path_prefix': '/v1/chat/completions', **bearer, 'metered': True}]}
(HERE / 'app-compose-meter.json').write_text(gch.to_deterministic_json(gch.AppCompose(
    runner='docker-compose', manifest_version=2, name='runner-meter-test', kms_enabled=True, egress=meter,
    docker_compose_file=json.dumps({'services': {'app': {'image': IMAGE, 'command': ['/bin/sh', '-c', METER]}}}))))
def simple(name, image, command, egress=None):
    return gch.to_deterministic_json(gch.AppCompose(runner='docker-compose', manifest_version=2, name=name, kms_enabled=True,
        egress=egress or {'max_requests': 0, 'max_tokens': 0, 'allow': []},
        docker_compose_file=json.dumps({'services': {'app': {'image': image, 'command': command}}})))


rq = lambda kind, url, hashes, **kw: {'provider_quote': {'kind': kind, 'attestation_url': url, 'compose_hashes': hashes, **kw}}
NEAR_ONCHAIN = {'rpc': 'https://mainnet.base.org', 'apps': ['0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae', '0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b']}
(HERE / 'app-compose-abalone.json').write_text(simple('runner-abalone-test', IMAGE, ['/bin/sh', '-c', ABALONE], {
    'max_requests': 8, 'max_tokens': 0, 'allow': [
        {'host': 'api.redpill.ai', 'method': 'GET', 'path_prefix': '/v1/models', **rq('redpill', 'https://api.redpill.ai/v1/aci/attestation', [REDPILL_COMPOSE])},
        {'host': 'tee.redpill.ai', 'method': 'GET', 'path_prefix': '/v1/models', **rq('redpill', 'https://tee.redpill.ai/v1/aci/attestation', ['00' * 32])},
        {'host': 'localhost:8443', 'method': 'GET', 'path_prefix': '/v1/replayed', **rq('phala', 'http://127.0.0.1:8795/v1/aci/attestation', [REDPILL_COMPOSE])},
        # The keyset attests openrouter.phala.com SPKI 1989293e..., but the host serves f1a8a26d... (2026-10-08).
        {'host': 'openrouter.phala.com', 'method': 'GET', 'path_prefix': '/v1/models', **rq('phala', 'https://inference.phala.com/v1/aci/attestation', [REDPILL_COMPOSE])},
        {'host': 'cloud-api.near.ai', 'method': 'GET', 'path_prefix': '/v1/models', **bearer,
         'provider_quote': {'kind': 'nearai', 'attestation_url': 'https://cloud-api.near.ai/v1/attestation/report', 'onchain': NEAR_ONCHAIN, 'model': 'deepseek-ai/DeepSeek-V3.1'}}]}))
(HERE / 'app-compose-key.json').write_text(simple('runner-key-test', IMAGE, ['/bin/sh', '-c', KEY]))
(HERE / 'app-compose-key2.json').write_text(simple('runner-key-test-2', IMAGE, ['/bin/sh', '-c', KEY]))
(HERE / 'app-compose-reenroll.json').write_text(simple('runner-reenroll-test', IMAGE, ['/bin/sh', '-c', REENROLL]))
(HERE / 'app-compose-tunnel.json').write_text(simple('runner-tunnel-test', PEER_IMAGE, ['node', '-e', TUNNEL],
    {'max_requests': 0, 'max_tokens': 0, 'allow': [], 'tcp': [{'host': '127.0.0.1', 'port': 8794}]}))
(HERE / 'app-compose-peer.json').write_text(simple('runner-peer-test', PEER_IMAGE, ['node', '-e', 'console.log(process.version)']))
(HERE / 'app-compose-peer-mismatch.json').write_text(simple('runner-peer-test', PEER_IMAGE.replace('4de0c490', '4de0c491'), ['node', '-e', 'console.log(process.version)']))
print(gch.get_compose_hash(main))
# Named volume on the peer image (runs as root): print what earlier boots of this app wrote, then append a fresh token.
# HOLD keeps the boot (and its volume lock) alive for 20 s after writing.
VOLUME = r'''
echo "== peer-id"; node -e 'require("http").request({socketPath: "/run/egress.sock", method: "POST", path: "/key", headers: {host: "runner.local"}}, (r) => r.pipe(process.stdout)).end(JSON.stringify({path: "peer-id"}))'; echo
echo "== before"; cat /abalone-ledger/ledger.txt
echo "== entries"; ls -A /abalone-ledger
echo "== mount"; grep ' /abalone-ledger ' /proc/mounts
echo "== marker"; cat /abalone-ledger/.abalone-persistent
echo "== wrote"; head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | tee -a /abalone-ledger/ledger.txt; echo >> /abalone-ledger/ledger.txt; echo
sync
'''
HOLD = r'''
echo "== holding"; sleep 20; echo "== held"; echo ok
'''
def volume(name, spec, extra=''):
    return gch.to_deterministic_json(gch.AppCompose(runner='docker-compose', manifest_version=2, name=name, kms_enabled=True,
        egress={'max_requests': 0, 'max_tokens': 0, 'allow': []}, docker_compose_file=json.dumps({
            'services': {'app': {'image': PEER_IMAGE, 'command': ['/bin/sh', '-c', VOLUME + extra], 'volumes': [spec]}},
            'volumes': {'ledger': {}}})))


(HERE / 'app-compose-volume.json').write_text(volume('runner-volume-test', 'ledger:/abalone-ledger'))
(HERE / 'app-compose-volume2.json').write_text(volume('runner-volume-test-2', 'ledger:/abalone-ledger'))
(HERE / 'app-compose-volume-hold.json').write_text(volume('runner-volume-hold-test', 'ledger:/abalone-ledger', HOLD))
# Durability probe: 3 lines each followed by `sync -f`, 1 without, then hold until the test SIGKILLs the runner.
DURABLE = r'''
for i in 1 2 3; do echo "synced-$i" >> /abalone-ledger/durable.txt; sync -f /abalone-ledger/durable.txt; done
echo unsynced >> /abalone-ledger/durable.txt
echo "== SYNCED"; sleep 600
'''
(HERE / 'app-compose-volume-durable.json').write_text(volume('runner-volume-durable-test', 'ledger:/abalone-ledger', DURABLE))
(HERE / 'app-compose-volume-bind.json').write_text(volume('runner-volume-bind-test', '/tmp/ledger:/abalone-ledger'))

# Task guests (Tasks.swift): the peer image's node drives the whole task API from inside the peer VM.
# test/task-image/ is the task image (archive at ../oci/task-test.oci.tar).
TASK_IMAGE = 'local/abalone-task-test@sha256:b286d55d4a2192e632610354908a93dd856adb15fe3303d072c6fd4acceb7947'
import base64, io, tarfile
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as t:
    data = b'hello from inputs\n'
    info = tarfile.TarInfo('hello.txt'); info.size = len(data); info.mode = 0o644
    t.addfile(info, io.BytesIO(data))
INPUTS_B64 = base64.b64encode(buf.getvalue()).decode()
TASKS = r'''
const http = require("http"), net = require("net"), crypto = require("crypto");
const S = "/run/egress.sock", IMAGE = "%IMAGE%", INPUTS = "%INPUTS%";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const tid = (n) => sha("task" + n).slice(0, 32);
// A connection the runner closes before answering (it sent no request in 2 s: Proxy.swift silentConnectionSeconds) is retried; counted.
let retries = 0;
const call = async (method, path, body) => { for (let i = 0; ; i++) { try { return await call1(method, path, body); } catch (e) { if (i === 3) throw e; retries++; } } };
const call1 = (method, path, body) => new Promise((done, fail) => {
  const data = body === undefined ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  const r = http.request({ socketPath: S, method, path, agent: false, headers: { host: "runner.local", connection: "close",
    ...(data ? { "content-type": "application/json", "content-length": data.length } : {}) } }, (res) => {
    const parts = []; res.on("data", (d) => parts.push(d)); res.on("end", () => done({ status: res.statusCode, body: Buffer.concat(parts) }));
  });
  r.on("error", fail); if (data) r.write(data); r.end();
});
const show = async (name, method, path, body) => { const r = await call(method, path, body); console.log(`== ${name}\nstatus=${r.status} ${r.body.toString().trim()}`); return r; };
const compose = (id, o = {}) => ({ manifest_version: 2, name: `abalone-task-${id}`, runner: "docker-compose", kms_enabled: false,
  docker_compose_file: JSON.stringify({ services: { task: { image: o.image || IMAGE, command: o.command || ["/bin/sh", "/entry.sh"],
    labels: { "abalone.task_id": id, "abalone.auth_hash": o.auth || "a".repeat(64), "abalone.inputs_root": "b".repeat(64) } } } }),
  egress: o.egress || { max_requests: 0, max_tokens: 0, allow: [], tcp: [] }, task: { resource: o.resource || "small" } });
const start = (name, id, o) => show(name, "POST", "/task/start", { task_id: id, compose: compose(id, o), inputs_tar_b64: INPUTS });
const status = async (id) => JSON.parse((await call("GET", `/task/status?id=${id}`)).body);
const until = async (id, states, ms = 60000) => { const t = Date.now(); for (;;) { const s = await status(id); if (states.includes(s.state) || Date.now() - t > ms) return s; await sleep(250); } };
const attach = async (id) => { for (let i = 0; ; i++) { const c = await attach1(id); if (c.head !== "closed" || i === 3) return c; retries++; } };
const attach1 = (id) => new Promise((done) => {
  const s = net.connect(S), c = { s, head: null, buf: Buffer.alloc(0), closed: false };
  s.on("connect", () => s.write(`CONNECT task-${id}.runner.local:1 HTTP/1.1\r\nHost: task-${id}.runner.local:1\r\n\r\n`));
  s.on("data", (d) => {
    c.buf = Buffer.concat([c.buf, d]);
    const e = c.buf.indexOf("\r\n\r\n");
    if (c.head === null && e >= 0) { c.head = c.buf.subarray(0, c.buf.indexOf("\r\n")).toString(); if (c.head.includes(" 200 ")) c.buf = c.buf.subarray(e + 4); done(c); }
  });
  s.on("close", () => { c.closed = true; if (c.head === null) { c.head = "closed"; done(c); } });
});
const waitFor = async (c, pred, ms = 20000) => { const t = Date.now(); while (!pred(c) && Date.now() - t < ms) await sleep(50); return pred(c); };
const line = (name, v) => console.log(`== ${name}\n${v}`);
(async () => {
  const [T1, T2, T3, T4, T5] = [1, 2, 3, 4, 5].map(tid);
  line("inputs_sha256", sha(Buffer.from(INPUTS, "base64")));
  await start("start", T1);
  await start("start_again", T1);
  await start("start_other_compose", T1, { auth: "c".repeat(64) });
  await start("start_image_not_admitted", tid(6), { image: "local/abalone-task-test@sha256:" + "0".repeat(64) });
  await start("start_egress", tid(7), { egress: { max_requests: 1, max_tokens: 0, allow: [{ host: "example.com", method: "GET", path_prefix: "/" }], tcp: [] } });
  await start("start_unknown_resource", tid(8), { resource: "huge" });
  await show("stop_body_over_1mib", "POST", "/task/stop", "x".repeat(2 << 20));
  // A connection silent for 2 s is closed by the runner; writing into it afterwards must not kill the runner (SIGPIPE).
  const quiet = net.connect(S); let quietClosed = false; quiet.on("error", () => {}); quiet.on("close", () => { quietClosed = true; });
  await sleep(3000); const closedFirst = quietClosed; quiet.write("x".repeat(1 << 20)); await sleep(1000);
  line("silent_then_write", `${closedFirst} ${(await call("POST", "/attest", { data: "after-silent" })).status}`);
  line("running", JSON.stringify(await until(T1, ["running", "failed"])));
  const a1 = await attach(T1); line("attach", a1.head);
  const a2 = await attach(T1); line("attach_second", a2.head); a2.s.destroy();
  line("ready_buffered", await waitFor(a1, (c) => c.buf.includes('{"ready":true}\n')));
  a1.s.write('{"n":1,"msg":"hello"}\n');
  line("echo", await waitFor(a1, (c) => c.buf.includes('{"n":1,"msg":"hello"}\n')));
  a1.s.end('{"op":"later"}\n'); await waitFor(a1, (c) => c.closed, 5000);
  await sleep(4000);
  const a3 = await attach(T1); line("reattach", a3.head);
  line("later_delivered", await waitFor(a3, (c) => c.buf.includes('{"later":1}\n{"later":2}\n'), 5000));
  a3.s.end('{"op":"flood"}\n'); await waitFor(a3, (c) => c.closed, 5000);
  await sleep(8000);
  line("dropped", JSON.stringify(await status(T1)));
  const a4 = await attach(T1); line("reattach_flood", a4.head);
  await waitFor(a4, (c) => c.buf.length >= 4194304, 20000); await sleep(500);
  line("flood_bytes", `${a4.buf.length} ${a4.buf.subarray(0, 4194303).every((b) => b === 120)} ${a4.buf[4194303] === 10}`);
  a4.buf = Buffer.alloc(0); a4.s.write('{"op":"exit"}\n');
  line("done", await waitFor(a4, (c) => c.buf.includes('{"done":true}\n')));
  line("closed_on_exit", await waitFor(a4, (c) => c.closed));
  line("exited", JSON.stringify(await until(T1, ["exited", "stopped", "failed"])));
  const c1 = await call("GET", `/task/collect?id=${T1}`), c2 = await call("GET", `/task/collect?id=${T1}`);
  line("collect", `${c1.status} ${c2.status} ${sha(c1.body)} ${sha(c2.body)}`);
  line("collect_b64", c1.body.toString("base64"));
  const a5 = await attach(T1); line("attach_after_exit", a5.head); a5.s.destroy();
  // Attach while booting, before the task's receipt chain exists (run_tests.sh: --dev-task-boot-delay-ms 3000): one
  // attachment opened and closed (detach before the chain), a second left open, stdin written in both.
  const T6 = tid(10);
  await start("start_early", T6);
  const e1 = await attach(T6); line("early_attach", `${e1.head} ${(await status(T6)).state}`);
  e1.s.end('{"n":"early1"}\n'); await waitFor(e1, (c) => c.closed, 5000);
  const e2 = await attach(T6); line("early_reattach", `${e2.head} ${(await status(T6)).state}`);
  e2.s.write('{"n":"early2"}\n');
  line("early_echo", await waitFor(e2, (c) => c.buf.includes('{"n":"early1"}\n') && c.buf.includes('{"n":"early2"}\n'), 30000));
  e2.s.write('{"op":"exit"}\n');
  line("early_done", await waitFor(e2, (c) => c.buf.includes('{"done":true}\n')));
  line("early_exited", JSON.stringify(await until(T6, ["exited", "stopped", "failed"])));
  line("early_collect_b64", (await call("GET", `/task/collect?id=${T6}`)).body.toString("base64"));
  await show("early_delete", "POST", "/task/delete", { task_id: T6 });
  await start("start_t2", T2); await start("start_t3", T3);
  await start("start_over_max", T4);
  // Peer traffic while two task VMs boot: 2 MiB uploads (413) and /attest, until both run plus 2 s.
  const ov = { n: 0, bad: [] }, t0 = Date.now(); let done2 = 0;
  while (!(done2 && Date.now() > done2 + 2000) && Date.now() - t0 < 60000) {
    const a = await call("POST", "/task/stop", "x".repeat(2 << 20)), b = await call("POST", "/attest", { data: "abalone-attest/1|peerA|peerB|ov" + ov.n });
    ov.n++; if (a.status !== 413 || b.status !== 200) ov.bad.push(`${a.status}/${b.status}`);
    if (!done2 && (await status(T2)).state === "running" && (await status(T3)).state === "running") done2 = Date.now();
  }
  line("overlap", `${ov.n} ${ov.bad.length} ${done2 ? "both_running" : "not_running"} ${ov.bad.join(" ")}`);
  line("t2_running", JSON.stringify(await until(T2, ["running", "failed"])));
  await until(T3, ["running", "failed"]);
  await show("delete_running", "POST", "/task/delete", { task_id: T3 });
  await show("collect_running", "GET", `/task/collect?id=${T3}`);
  await show("stop_t2", "POST", "/task/stop", { task_id: T2, grace_seconds: 1 });
  line("t2_stopped", JSON.stringify(await until(T2, ["stopped", "exited", "failed"])));
  await show("stop_t2_again", "POST", "/task/stop", { task_id: T2, grace_seconds: 1 });
  await start("start_t5_capped", T5, { resource: "capped" });
  line("t5_time_cap", JSON.stringify(await until(T5, ["stopped", "exited", "failed"])));
  line("collect5_b64", (await call("GET", `/task/collect?id=${T5}`)).body.toString("base64"));
  await show("stop_t3", "POST", "/task/stop", { task_id: T3, grace_seconds: 0 });
  line("t3_stopped", JSON.stringify(await until(T3, ["stopped", "exited", "failed"])));
  await show("delete_t1", "POST", "/task/delete", { task_id: T1 });
  await show("status_deleted", "GET", `/task/status?id=${T1}`);
  for (const t of [T2, T3, T5]) await show("delete", "POST", "/task/delete", { task_id: t });
  await start("start_left_running", tid(9));
  line("left_running", JSON.stringify(await until(tid(9), ["running", "failed"])));
  line("retries", retries);
  line("end", "ok");
})();
'''
HELPERS = TASKS[:TASKS.index('(async () => {')]
TASKS = TASKS.replace('%IMAGE%', TASK_IMAGE).replace('%INPUTS%', INPUTS_B64)
# One boot of the real abalone task image (archive ../oci/task.oci.tar): init, finish, then collect. Pi's model request goes unanswered; finish writes /out regardless.
REAL_IMAGE = 'local/abalone-task@sha256:453a55a9f13a110e530dce1050a79a9d4ba34dc367c6a7f7d9aaae50107365c6'
REAL = HELPERS.replace('%IMAGE%', REAL_IMAGE).replace('%INPUTS%', INPUTS_B64) + r'''(async () => {
  const T = tid("real"), o = { command: ["node", "/abalone/bin/task-guest.mjs"] };
  await start("real_start", T, o);
  line("real_running", JSON.stringify(await until(T, ["running", "failed"], 120000)));
  const a = await attach(T); line("real_attach", a.head);
  a.s.write(JSON.stringify({ t: "init", prompt: "Reply with OK.", model: "test-model", tools: ["read"], check: "git --version && cat hello.txt" }) + "\n");
  await sleep(5000);
  a.s.write(JSON.stringify({ t: "finish", reason: "runner test" }) + "\n");
  await waitFor(a, (c) => c.buf.includes('"t":"outputs"'), 60000);
  line("real_frames", a.buf.toString().split("\n").map((l) => l.slice(0, 300)).join("\n"));
  line("real_exited", JSON.stringify(await until(T, ["exited", "stopped", "failed"], 60000)));
  line("real_collect_b64", (await call("GET", `/task/collect?id=${T}`)).body.toString("base64"));
  await show("real_delete", "POST", "/task/delete", { task_id: T });
  line("end", "ok");
})();
'''
SMALL = {'cpus': 2, 'mem_mb': 2048, 'out_mb': 1024, 'max_seconds': 1800}
# "capped" is a test-only menu entry with a 3 s wall cap; the compose hash covers it like any other.
TASKS_POLICY = {'images': [TASK_IMAGE], 'max_concurrent': 2, 'resources': {'small': SMALL, 'capped': {'cpus': 1, 'mem_mb': 512, 'out_mb': 64, 'max_seconds': 3}}}
def tasks_compose(name, policy):
    return gch.to_deterministic_json(gch.AppCompose(runner='docker-compose', manifest_version=2, name=name, kms_enabled=True,
        egress={'max_requests': 0, 'max_tokens': 0, 'allow': []}, tasks=policy,
        docker_compose_file=json.dumps({'services': {'app': {'image': PEER_IMAGE, 'command': ['node', '-e', TASKS]}}})))


(HERE / 'app-compose-tasks.json').write_text(tasks_compose('runner-tasks-test', TASKS_POLICY))
(HERE / 'app-compose-tasks-overcap.json').write_text(tasks_compose('runner-tasks-test', {**TASKS_POLICY, 'resources': {'small': {**SMALL, 'max_seconds': 3600}}}))
(HERE / 'app-compose-tasks-real.json').write_text(gch.to_deterministic_json(gch.AppCompose(runner='docker-compose', manifest_version=2,
    name='runner-tasks-real-test', kms_enabled=True, egress={'max_requests': 0, 'max_tokens': 0, 'allow': []},
    tasks={'images': [REAL_IMAGE], 'max_concurrent': 1, 'resources': {'small': SMALL}},
    docker_compose_file=json.dumps({'services': {'app': {'image': PEER_IMAGE, 'command': ['node', '-e', REAL]}}}))))
