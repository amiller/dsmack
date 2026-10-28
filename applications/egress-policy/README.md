# Guest HTTP egress gateway

A guest-local HTTP gateway and non-recursive DNS stub. The gateway selects an
exact hostname policy from the HTTP Host, opens HTTPS to that name on port 443,
validates its certificate chain and hostname, and sends the same upstream Host.
It enforces methods, exact paths, application-byte budgets and request rates.

Run the Docker demonstration on a Linux builder with Docker Compose, Go and GCC:

```sh
cd applications/egress-policy
./demo.sh
```

The script builds on the builder, runs the race-enabled tests, then creates a
private workload network and a gateway with an uplink. A temporary NET_ADMIN
helper installs nftables rules in each container's namespace before the probe
runs. The workload and gateway run without capabilities. Results go to
`evidence/`; project containers, helpers, networks, the executable and the Go
cache are removed after the run. Remove the demo image after saving evidence:

```sh
docker image rm dsmack-egress-policy-20261027:prototype
```

`policy.json` holds the demonstration policy. `demo.py` embeds its bytes in
`configs.policy.content` in `demo-compose.json`, together with explicit
resolver bind mounts and the local content-addressed image ID. The DNS stub
answers allowed A queries with the gateway's private address, returns no AAAA
records, and refuses other names over UDP and TCP without forwarding them.

Configure a guest application with its API base URL using HTTP and port 8080,
for example `http://api.anthropic.com:8080`. The private hop ends at the gateway;
the upstream connection always uses validated HTTPS on port 443. To permit API
calls, choose `POST` and `/v1/messages` in the policy and set appropriate budgets.
The included public check uses `GET /` without credentials or model invocation.

Paths are exact and canonical; queries, encoded paths, absolute-form targets,
CONNECT, chunked requests and protocol upgrades are refused. The gateway creates
a fresh upstream request, forwards only Accept, Content-Type, Authorization,
X-Api-Key, Anthropic-Version and Anthropic-Beta, and fixes the User-Agent.
Redirects are returned to the client; each later request requires a new check.
Responses are buffered up to the rule's response limit.

Budgets apply across connections for one gateway lifetime. Upload accounting
sums body bytes, method, path, hostname, and forwarded header names and values.
Download accounting sums upstream response header names and values and body.
Framing, TLS, DNS and transport overhead are excluded. Requests and upload bytes
are charged before dialing, including failed attempts. Maximum response bytes
are reserved atomically, then unused bytes are returned. The rate is a token
bucket with a burst of one. A new gateway process starts a new budget.

Decision logs contain only rule index, allow/deny, fixed reason and byte counts.
Keep those logs in guest-private storage and deliver them through the user's
protected result channel. The demonstration keeps logs locally as test evidence.
