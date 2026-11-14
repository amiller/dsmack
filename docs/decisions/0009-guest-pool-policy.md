---
status: proposed
date: 2026-11-12
---

# Guests follow use: a small warm floor, and a lifetime set by the stay

## Context

A guest is one VM run on a Mac. It serves one stay, then retires.

The pool (`compute-node/pool.py`) fills every slot and keeps it full. Each guest lives one hour from boot. Its
replacement boots at `seconds//2 + 30`, whether or not anyone used it. What someone watching the New York Mac on
2026-11-12 saw:
- With one person on the demo, production ran 8 guest VMs (4 serving, 4 replacements booting early) for 4 usable
  slots: 32 GB of a 64 GB Mac.
- Staging allows one guest, so a single session showed "0 free slots".
- A guest nobody used was thrown away after an hour. One first used at minute 50 stopped admitting at minute 52.

Three rules produce this, and only one was ever argued for:

| Rule | Where | Since | Recorded reason |
|---|---|---|---|
| A guest serves one stay, then retires | `compute-node/peer/agent.go` | 2026-10-30, `a23d26d` | a later owner must not see files left in the workspace |
| A run lasts at most 3600 s from boot; admission closes 480 s before the end | `payments/guest/payments.go:139`, the measured compose | 2026-10-30, `661883f` | none |
| A run may make at most 64 App Attest assertions | `runner-vm/control-src/Sources/marAttest/GuestAttest.swift:28` | 2026-10-25, `f6b647b` | none |

The half-life replacement is left over from 2026-10-29, when guests lived 840 s. Then the overlap was about 6 minutes.
The compute-node README still says so. When guests became hour-long the formula stayed, and the overlap became 30
minutes.

The hour measures neither price nor use:
- Stays are already metered per second.
- A stay already ends after 300 s idle (`AGENT_IDLE_TIMEOUT_SECONDS`).
- The hour counts from boot, so it is mostly time spent waiting for someone.
- The 64 attestations behave like a timer only because idle guests re-register on a loop and each registration attests.

## What other systems do

**CI runners have our shape:** single use, a boot of about a minute, a fixed host budget.
- GitLab's instance and docker-autoscaler executors delete an instance after its one job (`max_use_count=1`). They keep
  `idle_count` idle instances under `max_instances`
  ([docs](https://docs.gitlab.com/runner/executors/instance.html)).
- GitHub's runner scale sets target `minRunners` plus one runner per job, capped at `maxRunners`
  ([docs](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets)).
- Daytona's warm pool keeps a fixed number of running sandboxes, and each claim starts a replacement
  ([docs](https://www.daytona.io/docs/en/warm-pools)).
- Agent Sandbox's `SandboxWarmPool` has a fixed size, scaled externally from claim rate × time to replenish one
  ([docs](https://agent-sandbox.sigs.k8s.io/docs/)).

None of them fills every slot ahead of demand, and none rotates idle instances on a fixed lifetime.

**Queueing research backs a small floor over none.** When servers take time to boot, keeping a few always on beats
turning everything off when idle ([Gandhi, Harchol-Balter, Adan 2010](https://www3.cs.stonybrook.edu/~anshul/perf_mmk_2010.pdf)).
A floor near the expected number of busy servers is close to optimal, and a floor of zero can be far from it
([Maccio, Down](https://www.cas.mcmaster.ca/~downd/acc_final.pdf)).

Serverless platforms size keep-alive from observed idle gaps. Shahrad et al.
([ATC 2020](https://arxiv.org/pdf/2003.03423)) beat fixed 10- and 20-minute windows that way.

**Sandbox platforms keep lifetime, idle release and billing apart:**
- **E2B** (open source, Firecracker): its timer starts when a sandbox is created for a user, 5 minutes by default. It
  is extended by explicit calls, with at most 1 h (Hobby) or 24 h (Pro) of continuous run. On timeout E2B can pause
  the sandbox instead of killing it, keeping memory and disk until the next request
  ([docs](https://docs.e2b.dev/faq/sandbox-lifetime)). It bills per second while running, with no stated minimum.
- **Daytona** stops a sandbox after 15 minutes with no SDK events.
- **Modal** separates `idle_timeout` from a maximum `timeout`, and counts a running command, input or an open
  connection as activity ([docs](https://modal.com/docs/guide/sandbox)).
- **Cloudflare Sandbox** sleeps after 10 idle minutes ([docs](https://developers.cloudflare.com/sandbox/api/lifecycle)).
- **Fly** bills a running Machine per second and a stopped one only for its disk
  ([docs](https://docs.fly.io/about/pricing)).

| | Open source | Isolation | Warm pool | What ends a sandbox |
|---|---|---|---|---|
| [E2B](https://github.com/e2b-dev/infra) | yes, Apache-2.0 | Firecracker | none; restores a snapshot on create | timer from creation, extended by call; pause or kill |
| [Daytona](https://www.daytona.io/docs/en/warm-pools) | yes | | fixed, replace on claim | 15 min idle → stop; 7 days → archive |
| [microsandbox](https://github.com/superradcompany/microsandbox) | yes | libkrun; Linux, Windows, Apple Silicon | | explicit; snapshot, fork |
| [Arrakis](https://github.com/abshkbh/arrakis) | yes | cloud-hypervisor | | explicit; snapshot |
| [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | yes | gVisor or Kata | fixed `replicas` | absolute time or delete |
| [Modal](https://modal.com/docs/guide/sandbox) | no | | | idle timeout, separate max |
| [Cloudflare](https://developers.cloudflare.com/sandbox/api/lifecycle) | no | container | | idle sleep |
| [Fly](https://docs.fly.io/about/pricing) | no | Firecracker | | stop on excess capacity |

None of these has our hard per-run attestation cap. The recipe below is ours.

## Decision

**Phase 1: a warm floor, replace on consume.** Pool code only; no guest build, no chain change.
1. **Cap.** At most `max_guests` guests run, booted or booting. Memory bounds it: (64 − 16) / 4 = 12 on a 64 GB Mac.
2. **Floor.** Keep `spares` idle, admitting guests, set in `operator.json`, default 1. Size it as at least the stays
   that arrive during one boot: ceil(arrivals per minute × 1 min) + 1.
3. **Replace on consume.** When a stay claims a spare, boot one guest at once to restore the floor.
4. **Rotate idle spares late.** Replace an idle spare only when it can no longer take a useful stay: 5 minutes before
   its admission closes (`pool.replace_after`), not at half-life.

One user then costs about 2 VMs instead of 8.

**Phase 2: lifetime set by the stay.** Needs a new guest build, its class registered on each escrow, broker changes,
and a re-signed runner (its code hash is checked on chain).
1. **Guest lifetime:** until its one stay ends. An unused guest waits as long as it is needed.
2. **Stay length:** ends after an idle window that resets on activity (a tool call, input, an open connection), or
   when its paid time runs out. It extends in increments while used and paid for.
3. **Price:** a minimum charge or increment size is a billing rule. It holds no VM up.
4. **Registration:** valid while the Mac's heartbeat shows the guest alive, not until a fixed expiry.
5. **Attestation:** a guest attests when a browser asks, so the 64 count tracks use. The runner counts per stay.

Phase 2 removes rule 4 of phase 1: with no lifetime, an idle spare never needs replacing.

## Options not taken

- **Keep every slot warm on a timer** (today). Cost scales with slots, not use.
- **Boot only on demand.** Every new conversation waits about a minute. The queueing results say a floor of zero is
  the wrong end.
- **Longer runs without changing what they count.** Raising 3600 s and 64 keeps idle time on the clock. It costs the
  same build and re-signing as phase 2 and fixes less.

## Consequences

- The freed memory can give staging a second slot.
- A burst larger than `spares` waits about a minute per extra guest.
- The page's free-slot count shows idle spares, not capacity. It should show both.

## Open questions

- **Why one hour and 64 attestations?** No reason is recorded. Phase 2 assumes they protect nothing that a per-stay
  bound cannot.
- **Snapshot restore.** E2B keeps no running VMs and restores a pre-booted snapshot on demand. Apple's Virtualization
  framework can save and restore VM state. If a restored guest can attest fresh, with a new run identity and key, a
  snapshot could replace idle spares.
- **Arrival data.** Once we have it, the floor can follow time of day, as in Shahrad et al.
