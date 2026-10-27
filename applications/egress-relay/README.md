# Attested egress relay

A v0.2 Mac guest serves SOCKS5 CONNECT over a libp2p circuit relay. Every recipient
TCP connection, including DNS resolution, uses a WireGuard userspace netstack.
The guest receives its WireGuard profile through the task-secret release policy
and `/v1/GetSecret`; the profile stays in memory. The service creates no kernel
WireGuard interface.

The uplink is a single-peer wg-quick profile with `PrivateKey`, `Address`, `DNS`,
`PublicKey`, `Endpoint` (an IP and port), and `AllowedIPs`. It also accepts `MTU`,
`PresharedKey`, and `PersistentKeepalive`. DNS servers are IP addresses; profile
hooks and unknown options are rejected.

The relay reuses [libp2p-attest](../libp2p-attest/README.md)'s peer identity and
attestation binding. A recipient checks `/dsmack/attest/1` with that application's
`verify.py` before opening its SOCKS listener. The attestation binds the authenticated
PeerId, guest image, measured compose and `peer` service.

## Build and pack

Run the builds on a Linux builder, from this directory:

```sh
(cd peer && CGO_ENABLED=0 go build -o ../dsmack-egress-amd64 . && CGO_ENABLED=0 GOARCH=arm64 go build -o ../dsmack-egress-arm64 .)
python3 workload.py <repo> <base image files> <canary-v1.app-compose.json> \
  dsmack-egress-arm64 <relay maddr> <task id> <policy url> <WireGuard IP:port> wl
```

The workload contains only the static executable. Its command measures the relay
address, task ID and policy URL. Its measured `network.egress` permits exactly
the WireGuard endpoint over UDP, the libp2p relay over TCP and the policy server
over TCP. Use IP literals for these endpoints (bracket IPv6 endpoints with ports).
The supervisor installs this allowlist before compose starts; recipient CONNECTs
and DNS travel inside WireGuard. Outputs
are `attestation` and `peer-id`. The service runs for 420 seconds.

Start a circuit relay using [libp2p-attest's relay command](../libp2p-attest/README.md).
Run a separate instance of [the release policy server](../../dstack-compat/secret-release/server.ts)
on the operator host. Its `config.json` task entry binds `manifest` to the workload's
`manifest_sha256` and `images` to its `os_image_hash`. Wrap the WireGuard client
profile with that server's `/public-key` and `server.ts wrap`; supply the profile
as hex on stdin. The guest requests release with an attestation binding the task
ID, then submits the sealed reply to `/v1/GetSecret`.

Copy `wl/disk/workload.img` and `wl/compose-manifest.json` into a run directory on
the Mac and launch with the installed v0.2 runner, base image and enrollment:

```sh
python3 ../libp2p-attest/run-mac.py <runner directory> <run directory>
```

## Connect

Once the relay logs the guest's reservation, run the recipient on the operator
host. Pass the exact workload manifest and the installed runner's enrollment,
CDHash and image hash to the verifier:

```sh
./dsmack-egress-amd64 recipient <relay maddr>/p2p-circuit/p2p/<guest> 127.0.0.1:1080 \
  python3 ../libp2p-attest/verify.py --enrollment <enrollment directory> \
  --manifest wl/compose-manifest.json --cdhash <runner cdhash> --os-image <os_image_hash>
curl --socks5-hostname 127.0.0.1:1080 https://ip.me
```

Each accepted local connection opens a `/dsmack/socks/1` stream to the verified guest.
SOCKS uses the no-authentication method and accepts CONNECT only. The WireGuard
server NATs those sessions to its internet uplink, so `ip.me` returns that server's
exit address.
