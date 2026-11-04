---
status: proposed
date: 2026-11-04
issue: https://github.com/amiller/dsmack/pull/82
---

# The guest learns about its host's network from a remote authority or a signed measurement plan

## Context

resip wants an attested answer to "is this line behind carrier-grade NAT?". The
obvious way is to run a traceroute in a container and sign the output with
`/v1/Attest`. That doesn't work, and the reason applies to every question of the
form "the guest needs to know X about its network or its host".

**What the guest is attached to.** The runner is the Rust HVF backend
(`hv_vm_create`), not Virtualization.framework
(`runner-vm/packaging/sign-production.md:55-57`). Its only network device is a
virtio-net fd that `mar` connects to a Unix socket named in `session.json`
(`runner-vm/app-src/Sources/mar/V3Launch.swift:83,201-206`). On the Mini the
launcher starts `gvproxy-darwin` on that socket
(`applications/compute-node/pool_mac_run.py:75-81`; resip's
`guest/run-mini.sh:10,18` calls it unchanged). The guest configures itself for
gvproxy v0.8.9's unconfigured NAT, `192.168.127.2/24` with gateway and DNS on
`.1` (`base-vm/browser-sandbox-v1/source/guest/supervisor-dstack-trixie.sh:133-147`).
gvproxy is a userspace stack: it terminates the guest's TCP and UDP and opens
new sockets on the Mac. So the guest has no raw path onto the Mac's network.
Whatever it sends, the first hop it can observe is gvproxy. Our notes record
only that the guest can't see the home router (resip
`notes/appraisal-schema.md:79`); none records a traceroute run from a guest,
and this record doesn't claim what one would print.

**Where policy is enforced.** Egress policy is not in gvproxy. The measured base
applies `network.egress` (and, with PR #78, `network.service_egress`) as
nftables inside the guest before compose starts
(`supervisor-dstack-trixie.sh:591-594`, `base-vm/browser-sandbox-v1/README.md:21-31`).
gvproxy would dial a LAN address if asked. The guest stays off the owner's LAN
because its egress list leaves out private ranges, as resip's gateway list does.
`192.168.127.254` reaches the Mac's loopback (`dstack-compat/secret_workload.py:6-7`),
which compute-node and browser-p2p use for their host proxies.

**What the attestation covers.** A verifier holding the Apple root and the
CDRegistry learns:

- the assertion came from an App Attest key enrolled for an approved build of
  `mar`. CDRegistry pins its code pages and entitlements (`contracts/src/CDRegistry.sol:5-23`);
- for launch and result: `manifest_sha256`, an evidence digest and the challenge
  (`AssertionEvidence.swift:83-95`). The evidence holds the observed kernel,
  initrd, system disk and workload hashes. Its only network field is the boolean
  `net_present` (`ReceiptMapperV3.swift:187`, checked at `:133-134`);
- for guest Attest: `os_image_hash || manifest_sha256 || run || event_head ||
  caller || report_data` (`control-src/Sources/marAttest/GuestAttest.swift:15-23`).

Nothing in any of these names gvproxy, its hash, the launcher or the session
file. `net_present: true` says a stream socket was connected. The other end
could be gvproxy, passt, or a program that rewrites every packet. The gvproxy
hash checks that exist are operator-side: `docs/canary/CLAIMING.md:67-69` has the
operator run `shasum -c`, and the pilot coordinator pins the helper
(`applications/pilot-client/coordinator/coordinator.py:130,221-222`). That
coordinator describes itself as "Trusted local operator glue. No evidence
validity" (`coordinator.py:2`). `pool_mac_run.py` runs whatever sits at
`~/.ap/runtime/helper/gvproxy-darwin`. A dishonest owner skips all of these, and
no verifier can tell.

**What changing the attested parts costs.** `mar` is the only process whose
claims verify. Any change to its code is a new CDHash: a signature from Andrew,
`setBuild` on the CDRegistry (`CDRegistry.sol:144`), which voids the previous
build's registrations, and a new enrollment pinned by consumers (resip
`web/verify.ts:39-40` refuses any other CDHash). Any change to the base image moves `os_image_hash`,
which every consumer's policy pins (`applications/compute-node/browser/sandbox.mjs:135-138`).
Paying either cost for each new question is what Andrew ruled out: the base
image is not to be tweaked for every slight variation.

## Options

**A. The guest asks a remote party over TLS.** The guest fetches the fact from
someone who will state it over publicly trusted TLS (an IP echo, an ISP's
account API) and signs it with `/v1/Attest`. No image or runner change. It is
limited to facts some remote party will say, and to the guest's egress path,
which may not be the line in question.

**B. One runner op per measurement.** PR #82 adds a `netprobe` op that measures
the Mac's line and returns a `behind_cgnat` verdict computed inside `mar`
(`runner-vm/control-src/Sources/marAttest/HostNetprobe.swift` `cgnatVerdict` on
`work/host-netprobe`). It works, and it is the first of these. The second
question, or a fix to the verdict rule, is another re-sign. The rule is new, and
the obvious version of it gets the line below wrong.

**C. One signed-once op that runs a plan.** The runner gets a fixed set of
measurement primitives, compiled in once: default route, ICMP probe at a TTL,
NAT-PMP and UPnP external address, HTTPS echo. A guest sends `{"op":"measure",
"plan": ...}`, where the plan is a short JSON list of primitive calls. The
runner runs it, builds a report of observations (address classes, hop kinds,
integer RTTs, salted address commitments; no raw addresses), and answers with a
guest Attest whose `report_data = sha256(plan) || sha256(report)` and whose
`caller = sha256("dsmack.host-measure/1\0")`. Compose service names can't hold a
NUL, so no `sha256(service name)` from `dstack-compat/agent.py` can collide with
it. Verdicts such as "CGNAT or not" are computed by the verifier from the
observations, not by `mar`.

Allow-listing works the way guest images already do: the runner admits any
well-formed plan, and the verifier accepts only the plan hashes on its own list,
next to its `os_image_hash` and CDHash pins. A new question is a new plan and a
list entry. A better rule is a verifier change.

Why a plan over compiled primitives and not a hash-pinned program: App Attest
identifies `mar` and nothing it spawns. A child process isn't covered by `mar`'s
hardened runtime, and `com.apple.security.cs.*` entitlements are forbidden
(`sign-production.md:50-57`), so `mar` can't host a JIT or load code either.
Feeding a helper's output into `mar` "would only have `mar` sign input it never
measured" (resip `notes/attested-host-probe.md:19`).

Constraints the op needs. Ctl frames are at most 4 KiB (`GuestCtl.swift:2`), so
plan, report and events must fit; #82's report is about 620 bytes. Primitives
must not become an egress bypass: ICMP targets are public IPv4 addresses, the
default gateway, or the echo-seen address; NAT-PMP goes to the gateway; SSDP
stays on the link; HTTPS goes only to URLs compiled into `mar`, as #82's three
echo services are, and returns a commitment, never a body. LAN results come back
as classes. Each primitive is unprivileged and read-only, as #82's are (ICMP
over `SOCK_DGRAM`).

Carrying the plan in the compose manifest, where `manifest_sha256` already binds
it, would be neater, but the guest's manifest validator refuses unknown
top-level keys
(`base-vm/browser-sandbox-v1/source/runner-content/lib/dsmack_compose_contract/manifest.py:609`),
so that is a base change. The ctl op is not.

**D. Give the guest a real network path.** Attach vmnet (shared or bridged), or
VZ's NAT, so a container sees TTLs and ICMP. The backend has no such device and
the runner holds only `com.apple.security.hypervisor` (`DsmackRunner.entitlements:18`),
so this is a runner change. vmnet's shared and bridged modes need root or
Apple's restricted `com.apple.vm.networking` entitlement (Apple's vmnet
documentation; not tested here). The guest's static gvproxy profile and every
manifest that uses `192.168.127.254` would change, so it is a base change too.
The owner's LAN would then be one hop away, and LAN isolation would rest on the guest's egress list alone, or on pf rules on the Mac
that nothing attests. The guest's measurement is no stronger than C's: the
owner still owns the wire.

**E. A pinned host helper next to gvproxy.** Not attested: helper hashes appear
in no assertion (see Context). A helper with its own App Attest key would be a
second build, and CDRegistry approves one build at a time.

## What each route proves against a dishonest owner

| Route | A verifier can conclude | A dishonest owner can still |
|---|---|---|
| Owner states it | nothing | say anything |
| E, pinned helper | nothing beyond the owner's word | run any helper |
| B or C, host measurement | the approved `mar` observed these classes and latencies on the network the Mac was attached to, during this guest run | route the Mac through a VPN on a router, answer ICMP for the echo address from a LAN box, or install a root CA that fakes the echo services. A VPN on the Mac's default route shows up as a tunnel interface; the rest does not |
| D, guest on vmnet | the same as C, seen from the guest | the same as C |
| A, remote authority | the named TLS origin said this to the measured guest | pick which account to log into; route the guest's egress elsewhere. A binding check (the guest's own egress address equals the address the authority reports) closes the second |

None of the host-side routes prove the network is the line as the ISP delivers
it. App Attest proves the binary. The independent check is an outside one, such
as an inbound connection to a forwarded port, or a lease holder comparing the
exit address against the salted commitment.

## Decision

Use A whenever a remote authority will state the fact. Otherwise use C. Rework
PR #82 as C's first plan: keep its I/O, make `netprobe` a `measure` plan, and
move `cgnatVerdict` from `mar` to the consumer.

For a new "the guest needs to know X about its network or host":

1. Can the guest get X from a remote party over TLS, through its own egress? Do
   that (A). No image or runner change.
2. Otherwise, can X be computed from observations the existing primitives make?
   Write a plan, publish its hash, and add it to the consumer's allow-list (C).
3. Re-sign the runner only for a new primitive (a kind of observation `mar`
   can't make yet), a new compiled-in remote target, a new entitlement, or a
   change to what the client data binds.
4. Change the base image only when the guest's own boundary must change: the
   manifest schema, the guest's network profile, or a security preset. Never to
   observe the host.

## Consequences

The first C build costs the same one re-sign that #82 already needs. After that,
CGNAT, double NAT, MTU or "is the default route a tunnel" are plans. A wrong
verdict rule is a verifier fix.

The primitive set becomes a reviewed surface that grows slowly. Each primitive
is a way for a guest to make the Mac send packets outside the guest's egress
list, so the destination rules above are part of the primitive.

## The case that prompted this

The Mini's line is double NAT: the owner's router behind an ISP gateway.
NAT-PMP from the inner router returns result 3, UPnP `GetExternalIPAddress` is
empty, and neither router reports a WAN address.

- Route A against the ISP, as observed on 2026-11-04. The gateway serves
  publicly trusted HTTPS (a Sectigo OV certificate issued to the ISP for its
  router hostname), but its status pages return "Access Denied": they are
  managed from the ISP's phone app, and the ISP's web portal for them is
  retired. So there is no TLS page to read on the LAN. A guest browser reading
  the account's WAN address from the ISP's web origin is a spike, blocked on
  finding a page that shows it.
- Route B, run unsigned through #82's code on the Mini, and its Python
  reference: `behind_cgnat: false`, reason
  `own_public_address_inside_access_link`. The public address answers at hop 2,
  at the gateway's LAN latency, before the step to ISP latency at hop 3. Hop 3 is
  a 10/8 ISP router. A rule of "a private hop past the home gateway means CGNAT"
  would have called this line CGNAT.
