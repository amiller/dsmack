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

The relay extends [libp2p-attest](../libp2p-attest/README.md)'s peer identity and
attestation binding with a run-specific Ed25519 receipt key. A recipient checks `/dsmack/attest/1` with that application's
`verify.py` before opening its SOCKS listener. The attestation binds the authenticated
PeerId, receipt key, guest image, measured compose and `peer` service.

## Build and pack

Run the builds on a Linux builder, from this directory:

```sh
(cd peer && CGO_ENABLED=0 go build -o ../dsmack-egress-amd64 . && CGO_ENABLED=0 GOARCH=arm64 go build -o ../dsmack-egress-arm64 .)
python3 workload.py <repo> <base image files> <canary-v1.app-compose.json> \
  dsmack-egress-arm64 <relay maddr> <task id> <policy url> <WireGuard IP:port> <broker public key hex> wl
```

The workload contains only the static executable. Its command measures the relay
address, task ID, policy URL and broker Ed25519 public key. Its measured `network.egress` permits exactly
the WireGuard endpoint over UDP, the libp2p relay over TCP and the policy server
over TCP. Use IP literals for these endpoints (bracket IPv6 endpoints with ports).
The supervisor installs this allowlist before compose starts; recipient CONNECTs
and DNS travel inside WireGuard. Outputs
are `attestation`, `peer-id`, `receipt-key` and `receipts`. The service runs for 420 seconds.

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

## Connect and fetch

Generate a local test-credit signing key on the client/broker machine before
packing the workload, then pass its public key to `workload.py`:

```sh
python3 signer.py keygen test-broker.key
python3 signer.py key test-broker.key
```

One command obtains credit, verifies the measured compose and relay attestation,
starts local SOCKS, fetches a URL, and verifies a signed usage receipt:

```sh
python3 demo.py --binary ./dsmack-egress-amd64 \
  --peer <relay maddr>/p2p-circuit/p2p/<guest> --signer-key test-broker.key \
  --client-key test-client.key --out demo --url https://ip.me -- \
  python3 ../libp2p-attest/verify.py --enrollment <enrollment directory> \
  --manifest wl/compose-manifest.json --cdhash <runner cdhash> --os-image <os_image_hash>
```

Use `--broker-url <URL>` to fetch `GET /key` (`public_key`, hex) and
`POST /grant` (`relay_peer`, `client_peer`, `bytes`) from the broker instead of
the local signer. Credit is free testnet credit; the broker owns rate limits
and the payment authorization seam. `--grant <file>` presents an existing grant,
`--bytes` selects the budget, and `--ttl` selects a local grant's lifetime.
Private signing seeds stay on the machine that generated them.

For a long-running listener, generate a client identity with `dsmack-egress keygen
client.key`, read it with `dsmack-egress id client.key`, mint a grant for that
PeerId, then run:

```sh
./dsmack-egress-amd64 recipient <circuit maddr> 127.0.0.1:1080 client.key grant.json \
  python3 ../libp2p-attest/verify.py --broker-key <hex> --enrollment <dir> \
  --manifest wl/compose-manifest.json --cdhash <hex> --os-image <hex>
curl --socks5-hostname 127.0.0.1:1080 https://ip.me
```

Each `/dsmack/socks/1` stream starts with a four-byte big-endian JSON byte length
(maximum 4096), followed by the canonical signed grant, then SOCKS5. The guest
checks the broker signature, relay identity, Noise-authenticated client identity,
expiry and remaining budget before SOCKS. The shared grant format is sorted-key,
compact UTF-8 JSON with `v:1`, a 32-character hex `grant_id`,
`relay_peer`, `client_peer`, integer `bytes` and Unix-seconds `expires_at`; `sig`
is the hex Ed25519 signature over those fields without `sig`.

Counters aggregate successfully forwarded TCP payload in both directions across
all streams for one grant, including TLS and HTTP bytes. Grant frames and SOCKS
negotiation are excluded. Exhaustion closes every stream using that grant and
refuses reuse; expiry sets deadlines on both stream and uplink.

`/dsmack/attest/1` returns JSON `{attestation:<hex>,receipt_key:<hex>}`. Its
`report_data` is `sha256("dsmack-libp2p-peer/1" || PeerId bytes) || receipt_key`.
The first half preserves the existing PeerId binding; the second half contains
the 32-byte Ed25519 public key. The broker key is the final measured `serve`
command argument. `verify.py --broker-key` requires both bindings.

`/dsmack/receipt/1` returns the authenticated client's cumulative receipts.
At shutdown, the `receipts` artifact contains all grants' final receipts. Each
receipt is `{grant_id,bytes_used,client_peer,relay_peer,run,sig}`; the signature
covers canonical JSON without `sig`. `run` is the hex run hash from `/v1/Info`
and the verified attestation. `verify.py --broker-key ... --receipts FILE` checks
the signatures, run and relay identity against that attestation.

Run the grant, accounting, SOCKS and WireGuard parser tests on the builder:

```sh
(cd peer && go test -race ./...)
```
