# Guest PromptGuard monitor

`none` and `baseline-pg2` are the only registered policies. `workload.py` reads
`monitor` from its optional operator JSON (default `none`) and measures the
canonical policy and its SHA-256 in the compose environment. The OCI digest
measures the gateway, worker and model files. The browser checks the registry
entry against that environment and displays the selected policy in guest
verification details.

The Pi page uses NEAR TEE by default or a browser-selected model provider.
For `baseline-pg2`, the page also sends the first prompt before inference, and the complete assistant
response on each tool call, through the authenticated Noise MCP session. The
guest gateway owns an offline CPU classifier; MCP invokes its loopback endpoint.
Repository import tool arguments are scanned before pre-flight. A pre-flight
denial applies to the next model tool call; each subsequent call checks the
complete response again. These MCP checks run independently of the model provider
and also run when model requests go directly from the browser on a user key.
The denied call returns `isError: true` with
`PG2_PROMPT_ATTACK` and the job continues. Missing response context returns
`MONITOR_CONTEXT_REQUIRED`. Classifier failures propagate as errors. No monitor
decisions enter gateway audit events or host/broker receipts. The worker denies
socket syscalls with seccomp across its threads and emits only fixed-size codes.

Build the ordinary compute image using `../../compute-node/README.md`, then:

```sh
python3 applications/egress-policy/monitor/fetch.py applications/egress-policy/monitor/weights
docker build -f applications/egress-policy/monitor/Dockerfile -t compute-node-pg2 .
```

The upstream Meta repository requires approved model access. `fetch.py` uses
`HF_TOKEN` only when explicitly supplied by the builder, and verifies upstream
digests before loading. Credentials stay outside the image build context.

Export `compute-node-pg2` as the OCI layout for `workload.py`; set
`"monitor":"baseline-pg2"` in its operator JSON. Use the resulting OCI digest
and exact compose manifest when registering a fresh compute class. Choose a new
`PAYMENTS_CONFIG.node` value and add it to the payments config's `classes` before
packing. Register with the existing contract:

```sh
deno run -A applications/payments/register-class.mjs PAYMENTS_CONFIG FUNDING_KEY \
  OUT/compose-manifest.json BROKER_URL PUBLISHER_ADDRESS
```

Set the page's `sandbox-policy.json` `manifest` to the exact new manifest's hex
bytes, retaining its enrollment/build pins. Add the class to the page/broker
class configuration, then rebuild the page with `npm ci && npm run build`.
Install the packed guest workload on the Mac pool and rotate guests. The signed
Mac runner, relay broker and contracts need no code changes or redeploys.

Measure on zed with a native CPU image using the same pinned dependencies:

```sh
docker build -f applications/egress-policy/monitor/Benchmark.Dockerfile -t dsmack-pg2-benchmark .
docker run --rm --network none --cpuset-cpus=0 --cpus=1 \
  --memory=4g --memory-swap=4g \
  dsmack-pg2-benchmark /opt/monitor/benchmark.py /opt/monitor/weights
```

This prints load time, first/warm classification latency, and peak process RSS
for two benign prompts, two malicious prompts and a long prompt. The container's
cgroup enforces one CPU and 4 GiB with no swap. Run real-model tests in that image:

```sh
docker run --rm --network none --cpuset-cpus=0 --cpus=1 \
  --memory=4g --memory-swap=4g --workdir /opt/monitor \
  -e PG2_WEIGHTS=/opt/monitor/weights --entrypoint /opt/monitor/venv/bin/python \
  compute-node-pg2 -m unittest -v test_promptguard
```

The local browser/MCP flow uses a deterministic classifier to exercise pre-flight,
failed tool results and continued execution:

```sh
cd applications/private-agent-web
EVIDENCE=/absolute/evidence/path node monitor.browser.test.mjs
```
