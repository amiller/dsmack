# Browser to an attested Mac through quick tunnels

A static IPFS page discovers relay addresses from a public index and a Base
Sepolia registry. It takes their union, shows each source and URL it tries,
skips stale connections, and verifies the guest's App Attest assertion and
Noise-authenticated PeerId before echoing. No Cloudflare account or fixed
hostname is needed.

The page pins an Apple-verified enrollment key and a workload template. Only the
tunnel hostname and relay PeerId vary in the measured compose. The browser
reconstructs the exact manifest hash using the discovered values; image, binary,
gateway policy, caller and the other compose fields remain pinned. Event replay
and authenticator checks reuse `dstack-compat/secret-release/policy.mjs`.

Build on a Linux builder, from the repository root:

```sh
(cd applications/libp2p-attest/peer && \
  CGO_ENABLED=0 go build -o ../browser-relay ./browser-relay && \
  CGO_ENABLED=0 go build -o ../dsmack-peer . && \
  CGO_ENABLED=0 GOARCH=arm64 go build -o ../browser-guest-arm64 ./browser-guest)
(cd applications/egress-policy && \
  CGO_ENABLED=0 GOARCH=arm64 go build -o ../libp2p-attest/egress-policy-arm64 .)
applications/libp2p-attest/dsmack-peer keygen relay.key
applications/libp2p-attest/browser-relay relay.key
# In another terminal; retain the printed hostname and relay PeerId:
cloudflared tunnel --no-autoupdate --url http://127.0.0.1:4019
```

The relay listens on loopback only. It accepts eight reservations and four
circuits per peer, with two-minute and 8 MiB limits per circuit/direction, allowing sealed model transcripts.

Pack the guest with a base image that applies the measured egress policy:

```sh
python3 applications/browser-p2p/workload.py --base BASE --reference REFERENCE \
  --peer applications/libp2p-attest/browser-guest-arm64 \
  --gateway applications/libp2p-attest/egress-policy-arm64 \
  --ca /etc/ssl/certs/ca-certificates.crt --hostname HOST --relay-peer RELAY --out wl
```

On the Mac, run `applications/compute-node/connect-proxy.py --listen 127.0.0.1
--port 18290 --model-host HOST`, then launch with the libp2p application's
`run-mac.py`. The guest's firewall admits only `192.168.127.254:18290`, gvproxy's
host-loopback alias. The measured gateway performs TLS through that CONNECT
proxy and permits bounded WebSocket upgrades to `*.trycloudflare.com` on port
443. The peer dials only its guest-local gateway. The wrapper also checks that
a direct connection to `1.1.1.1:443` is blocked and exports its result and gateway
log. The browser's connection address is the public tunnel hostname.

Build the static page and the small owner-written discovery registry:

```sh
cd applications/browser-p2p
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci
npm run build
npm run contract
python3 publish.py deploy --key FUNDING_WALLET --bytecode \
  contract-build/TunnelIndex_sol_TunnelIndex.bin --evidence DEPLOY_EVIDENCE
python3 bootstrap.py --enrollment ENROLLMENT --manifest COMPOSE --cdhash CDHASH \
  --registry REGISTRY_ADDRESS --output dist/config.json
ipfs add -Qr --pin=true dist
```

`bootstrap.py` supplies public CORS RPCs and defaults the fast index to
`https://pod.dstack.soc1024.com/private-agent/tunnels`. The private-agent server
hosts that index alongside its existing static files; its deploy helper accepts
`--operator-token-sha256`. The relay-broker server also includes `/tunnels`.

After the guest reserves, publish an entries JSON array containing
`{url:"wss://HOST/",relayPeer:"RELAY",guestPeer:"GUEST",expiresAt:UNIX_SECONDS}`.
Each expiry is at most one hour ahead. The registry owner and the index operator
publish the same hints:

```sh
python3 publish.py publish --key FUNDING_WALLET --registry REGISTRY_ADDRESS \
  --entries entries.json --broker INDEX_URL --operator-token OPERATOR_TOKEN \
  --evidence PUBLICATION_EVIDENCE
```

The helper records a transaction hash before sending and never resends it.
`publish.py broker --entries entries.json --broker INDEX_URL --operator-token
OPERATOR_TOKEN --evidence HTTP_EVIDENCE` performs only the HTTP publication.
Use it if the chain write succeeded and the HTTP index was unavailable.

Open `http://localhost:GATEWAY/ipfs/CID/`, with no target fragment. Changing the
quick-tunnel hostname requires new hints and guest inputs, while the page CID
stays the same.

After the guest halts, preserve its compressed result disk, assertions and logs,
verify them, then use the existing guarded cleanup helper to retire owned disks.
Publish an empty entries array, stop the owned tunnel/relay/proxy/gateway and
export `ipfs dag export CID > page.car`. Keep evidence and the static archive;
remove installs, compiled files and workload staging.

## Mac guest lifecycle

`mac-pool.py` runs the capped relay, quick tunnel and host CONNECT proxy alongside
one launch through the existing `libp2p-attest/run-mac.py` driver. It waits for
another Mac lane to finish, packs public inputs locally, publishes the guest
locator to both discovery sources, and refreshes the HTTP lease every minute.
The tunnel stops after the guest closes and both sources are cleared. It installs
no service, launchd agent or daemon. Each invocation uses a fresh state directory. Pass `--seconds 120` for a short
proof run; the default guest lifetime is 420 seconds.

Generate the publisher key on the Mac (`eth_account.Account.create()`), save it
with mode 0600, and keep it there. Fund its address with 0.001 Base Sepolia ETH.
Deploy `TunnelIndex` with that address as `--registry-owner`; the funding wallet
stays on its original machine. The Mac needs Python `eth-account==0.13.7` and
`eth-abi==5.2.0`, the Darwin arm64 relay/cloudflared binaries, Linux arm64 guest
and gateway binaries, the reference compose, CA bundle, and installed runner/base.
Signed HTTP publication uses this same Mac-local key and needs no operator token.
Each publisher replaces only its own expiring HTTP hints; the page verifies the
guest independently of the publisher.

Cross-build the Mac relay on the Linux builder:

```sh
(cd applications/libp2p-attest/peer && \
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o ../browser-relay ./browser-relay)
```

```sh
python3 applications/browser-p2p/mac-pool.py --state RUN --runner RUNNER \
  --reference REFERENCE --peer BIN/browser-guest-arm64 \
  --gateway BIN/egress-policy-arm64 --ca ca-certificates.crt \
  --relay BIN/browser-relay --cloudflared BIN/cloudflared \
  --publisher-key publisher.key --publisher-address ADDRESS --registry REGISTRY
```

Ctrl-C or SIGTERM drains the current guest before clearing
hints and stopping the tunnel, relay and proxy. Preserve and verify the original
VM result and logs, then retire its exact owned disks using the guarded cleanup
helper. Keep `publisher.key` and `relay.key` on the Mac for later launches.
