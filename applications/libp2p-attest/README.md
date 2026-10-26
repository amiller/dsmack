# Attested libp2p peer

A dsmack Mac guest as a libp2p peer that a remote peer can check before talking to it.
The guest has no inbound path, so it dials out to a circuit relay v2 and is reached at
`<relay>/p2p-circuit/p2p/<guest>`.

| Piece | Where | What it does |
|---|---|---|
| `dsmack-peer relay` | container on the operator host | circuit relay v2 with no data or duration limits; logs each reservation |
| `dsmack-peer serve` | the guest's one compose service | fresh Ed25519 identity, reserves a relay slot, calls `/v1/Attest` with `report_data = sha256("dsmack-libp2p-peer/1" ‖ PeerId bytes)` padded to 64 bytes, serves the attestation on `/dsmack/attest/1` and echoes on `/dsmack/echo/1` |
| `dsmack-peer dial` + `verify.py` | the remote peer | fetches `/dsmack/attest/1`, runs `verify.py` with the PeerId the connection authenticated, opens the echo stream only if it exits 0 |

`verify.py` checks the runner key's enrollment under the CDHash policy, the assertion over the
rebuilt client data and sealed event log, the image and compose manifest, the caller tag of the
`peer` service, and that `report_data` binds the PeerId. A peer presenting someone else's
attestation fails the last check. With `--run` it also ties the Attest to the launch assertion,
which the runner writes after the VM halts.

## Run

```sh
(cd peer && CGO_ENABLED=0 go build -o ../dsmack-peer-amd64 . && CGO_ENABLED=0 GOARCH=arm64 go build -o ../dsmack-peer-arm64 .)
./dsmack-peer-amd64 keygen relay.key
docker build -f relay.Dockerfile -t dsmack-libp2p-relay .
docker run -d --network host -v $PWD/relay.key:/relay.key:ro dsmack-libp2p-relay relay /ip4/<host ip>/tcp/4012 /relay.key
python3 workload.py <repo> <base image files> <canary-v1.app-compose.json> dsmack-peer-arm64 <relay maddr> wl
# on the Mac, with wl/disk/workload.img and wl/compose-manifest.json in <run dir>:
python3 run-mac.py <dir with DsmackRunner.app, base/, enrollment/> <run dir>
# once the relay logs the guest's reservation:
./dsmack-peer-amd64 dial <relay maddr>/p2p-circuit/p2p/<guest> python3 verify.py --enrollment <dir> \
  --manifest wl/compose-manifest.json --cdhash <runner cdhash> --os-image <os_image_hash>
```

The manifest uses `network.mode: nat`; the relay address is a measured argument of the service.
