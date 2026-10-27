# Compute node

A v0.2 guest daemon accepts one coding job at a time through a libp2p circuit
relay. It generates its identity, P-256 bundle key and Ed25519 receipt key at
boot, binds them with App Attest, and renews its broker registration every
25 seconds. Jobs and results use the [job protocol](PROTOCOL.md).

The image pins Claude Code 2.1.187 and `claude-opus-4-8`. `worker.py` calls
`agent-turns/find.py` for one edit turn. `/run/dsmack` points to the container's
`/dev/shm` tmpfs; the worker checks the mount before opening a credential. Its
sentinel reads `/run/dsmack/credential`, and both the credential and temporary
work tree are removed after the job. Outputs travel over pipes and are sealed
before leaving the daemon. The sole result artifact is public registration.

## Build on a Linux builder

From the repository root, with the qualified Claude image available locally:

```sh
(cd applications/compute-node/peer && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dsmack-compute .)
docker build -f applications/compute-node/Dockerfile \
  --build-arg QUALIFIED_CLAUDE_REPOSITORY=QUALIFIED_LOCAL_REPOSITORY \
  -t compute-node .
```

Export that image as a gzip OCI layout. Pack it with a starter compose manifest
whose `base_vm` describes the installed base image:

```sh
python3 applications/compute-node/workload.py REPO BASE STARTER OCI_DIR \
  sha256:IMAGE_DIGEST applications/compute-node/dsmack-compute \
  /ip4/RELAY_IP/tcp/RELAY_PORT/p2p/RELAY_ID \
  http://BROKER_IP:BROKER_PORT BROKER_ED25519_HEX RUNNER_CDHASH OUT 1800
```

The packer resolves the broker hostname once and measures its fixed `BROKER_IP`.
The node dials that IP while preserving the HTTPS hostname for certificate
verification. The guest allowlist contains exactly that endpoint, the circuit relay, and `192.168.100.3:18443`. Run the CONNECT proxy
on zed with `python3 applications/compute-node/connect-proxy.py`. It permits
only `CONNECT api.anthropic.com:443`; the sentinel verifies provider TLS in
its guest process. Its measured `HTTPS_PROXY` config selects the tunnel.

Admit the resulting compose/image/CDHash tuple at the broker, then launch the
workload using the installed v0.2 runner and the public `workload.img`, with no
private input disk. `GET /nodes` discovers live compute nodes. The daemon's
`serve` arguments are `RELAY SECONDS BROKER_URL BROKER_KEY CDHASH WORKER`.

## Transport helper

The same Go binary builds for a client host. `keygen FILE` creates its libp2p
key, `id FILE` prints the PeerId, and `sign FILE` signs a canonical JSON object
read on stdin. `exchange CIRCUIT KEY` relays framed stdin/stdout over
`/dsmack/job/1`. The client must verify discovery before using `exchange` and
wait for `ready` before sending its encrypted bundle.

## Test

```sh
(cd applications/compute-node/peer && go test -race ./...)
python3 -m unittest discover -s applications/compute-node -p 'test_*.py'
node --test applications/relay-broker/broker.test.mjs
```
