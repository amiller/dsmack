"""Relay stall reproducer (not part of run_tests.sh: about a minute per round, and the stall is intermittent).
Writes a peer compose whose node driver sends 2 MiB uploads (413) to runner.local back to back while three task VMs boot
in turn, and prints any upload that took over 1 s. A connection opened while a task VM starts can get no bytes from the
guest relay, and later connections wait behind it until the runner closes it (2 s, Proxy.swift silentConnectionSeconds); the driver
then retries. Before that close existed the stall lasted until the 120 s idle timeout, and the runner died of SIGPIPE.
Laptop: python3 test/relay_stress.py /tmp/stress.json; mini: bin/runner run --compose stress.json ... --task-archive
../oci/task-test.oci.tar (KMS allowing `bin/runner check stress.json`), then grep ' #' out/guest_stdout.txt.
"""
import runpy, sys
from pathlib import Path
g = runpy.run_path('test/gen_compose.py')
body = r'''(async () => {
  const big = "x".repeat(2 << 20), ok = JSON.stringify({ task_id: "0".repeat(32), grace_seconds: 1, pad: "y".repeat(900 << 10) });
  const timed = async (name, f) => { const t = Date.now(); const r = await Promise.race([f(), sleep(20000).then(() => ({ status: "TIMEOUT", body: Buffer.alloc(0) }))]); console.log(`${name} ${r.status} ${Date.now() - t}ms`); };
  for (let i = 0; i < 40; i++) await timed("idle_413", () => call("POST", "/task/stop", big));
  for (let i = 0; i < 5; i++) await timed("idle_900k", () => call("POST", "/task/stop", ok));
  for (let k = 1; k <= 3; k++) {
    await start("start", tid(100 + k));
    const t0 = Date.now(); let n = 0, slow = 0;
    while (Date.now() - t0 < 6000) { const t = Date.now(); const r = await Promise.race([call("POST", "/task/stop", big), sleep(15000).then(() => ({ status: "TIMEOUT" }))]); n++; if (r.status !== 413 || Date.now() - t > 1000) { slow++; console.log(`boot${k} #${n} ${r.status} ${Date.now() - t}ms at +${t - t0}ms`); } }
    console.log(`boot${k} ${n} uploads, ${slow} slow/failed`);
    await timed(`boot${k}_attest`, () => call("POST", "/attest", { data: "x" }));
    await until(tid(100 + k), ["running", "failed"]);
    await show("stop", "POST", "/task/stop", { task_id: tid(100 + k), grace_seconds: 0 });
  }
  line("end", "ok");
})();
'''
script = g['HELPERS'].replace('%IMAGE%', g['TASK_IMAGE']).replace('%INPUTS%', g['INPUTS_B64']) + body
gch = g['gch']; import json
Path(sys.argv[1]).write_text(gch.to_deterministic_json(gch.AppCompose(runner='docker-compose', manifest_version=2, name='stress', kms_enabled=True,
    egress={'max_requests': 0, 'max_tokens': 0, 'allow': []}, tasks={**g['TASKS_POLICY'], 'max_concurrent': 3},
    docker_compose_file=json.dumps({'services': {'app': {'image': g['PEER_IMAGE'], 'command': ['node', '-e', script]}}}))))
