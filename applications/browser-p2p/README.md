# Static browser to an attested guest

A static js-libp2p page connects to a Mac guest through a WebSocket circuit relay
behind Cloudflare Tunnel. The page verifies the guest's App Attest assertion,
measured image and compose, caller, and Noise-authenticated PeerId before echoing.
`bootstrap.py` verifies the enrollment against Apple's root and embeds its public
key and expiration in the page. The page CID commits to those operator-selected
trust pins. Event-log replay and authenticator checks reuse `policy.mjs`.

Build on a Linux builder, starting at the repository root:

```sh
(cd applications/libp2p-attest/peer && \
  CGO_ENABLED=0 go build -o ../browser-relay ./browser-relay && \
  CGO_ENABLED=0 go build -o ../dsmack-peer . && \
  CGO_ENABLED=0 GOARCH=arm64 go build -o ../dsmack-peer-arm64 .)
applications/libp2p-attest/dsmack-peer keygen relay.key
applications/libp2p-attest/browser-relay relay.key
# In another terminal; copy the printed hostname and relay PeerId:
cloudflared tunnel --no-autoupdate --url http://127.0.0.1:4019
```

The relay listens only on `127.0.0.1:4019`, accepts eight reservations and four
circuits per peer, and limits each circuit to two minutes and 128 KiB in each
direction. It logs reservation and connection requests. Both clients use
`/dns4/HOST/tcp/443/wss/p2p/RELAY`. The browser targets that address followed by
`/p2p-circuit/p2p/GUEST`.

Prepare the guest with `applications/libp2p-attest/workload.py` and launch it
with that application's `run-mac.py`. Supply the builder's
`/etc/ssl/certs/ca-certificates.crt` as the optional last workload argument to
include HTTPS roots in the scratch OCI image. The reference compose must name
the same base image files passed to the packer. The guest uses ordinary NAT.

Build and pin the page:

```sh
cd applications/browser-p2p
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci
npm run build
python3 bootstrap.py --enrollment ENROLLMENT --manifest COMPOSE \
  --cdhash RUNNER_CDHASH --output dist/config.json
# Use an owned Kubo repository with a loopback API and gateway.
ipfs add -Qr --pin=true dist
```

Open `http://localhost:GATEWAY/ipfs/CID/#target=CIRCUIT_MULTIADDR`. The fragment
stays in the browser. For HTTPS gateways, use the same CID and fragment.

`probe.mjs PAGE_URL EVIDENCE_DIR` runs Chromium through Playwright and saves the
browser result, original attestation, screenshot and WebSocket HTTP handshake
records. Run it in the matching Playwright 1.49.1 container on the builder with
the source and evidence directory mounted. The page makes one public WSS dial
and same-origin static-file requests.

After the guest finishes, preserve its result disk, launch/result assertions and
logs, then use the operator's guarded cleanup helper to retire owned scratch and
staged disks. Stop the relay, tunnel and temporary gateway, export the page with
`ipfs dag export CID > page.car`, and keep the static archive and evidence. Remove
`node_modules`, `dist`, workload staging and built executables after the probe.
