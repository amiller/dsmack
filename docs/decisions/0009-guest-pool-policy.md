---
status: proposed
date: 2026-11-12
---

# How many guests a Mac keeps running, and when it boots new ones

## Context

A guest is one VM run on a Mac. Three rules shape it today, and only one of them was ever argued for:

| Rule | Where | Since | Recorded reason |
|---|---|---|---|
| A guest serves one stay, then retires | `compute-node/peer/agent.go` | 2026-10-30, `a23d26d` | a later owner must not see files left in the workspace |
| A run lasts at most 3600 s; admission closes 480 s before the end | `payments/guest/payments.go:139`, the measured compose | 2026-10-30, `661883f` | none |
| A run may make at most 64 App Attest assertions | `runner-vm/control-src/Sources/marAttest/GuestAttest.swift:28` | 2026-10-25, `f6b647b` | none |

The pool (`compute-node/pool.py`) fills every slot and keeps it filled. Each slot's replacement boots at
`seconds//2 + 30`, whether or not anyone used the old guest. That formula dates from 2026-10-29, when guests lived
840 s: replace at 450 s, stop admitting at 570 s, exit at 840 s, about 6 minutes of overlap. The compute-node README
still describes that. The next day guests became hour-long and the formula stayed, so the overlap grew to 30 minutes.
Nobody chose 30 minutes.

What someone watching the New York Mac on 2026-11-12 saw:
- With one person using the demo, production ran 8 guest VMs (4 serving, 4 replacements booting early) for 4 usable
  slots, 32 GB of a 64 GB Mac.
- Staging allows one guest, so a single session showed "0 free slots".
- Every finished conversation throws its guest away and the pool boots another, even when nobody is waiting.
- A reload on staging could not start its replacement: the one slot was held by the old guest, and the overlap
  needs a second.

## Options

1. **Keep every slot warm, rotate on a timer** (today). No user ever waits for a boot. Cost scales with slots, not with
   use: N slots cost up to 2N VMs around the clock.
2. **Keep a few idle spares, boot more on demand, cap at the slot count.** Count idle, admitting guests. When there are
   fewer than `spares`, boot one; when a stay takes a spare, that is the trigger. An idle spare that reaches its
   admission close is replaced shortly before, not at half-life. One user costs about `spares + 1` VMs.
3. **Boot only on demand.** Nothing runs idle. Every new conversation waits about a minute for its guest.
4. **Longer runs.** Raise the 3600 s and 64-attestation caps so an idle spare lives longer and rotates less. Needs a new
   guest build, its class registered on each escrow, and a re-signed runner (its code hash is checked on chain).
   Combines with 2.
5. **No timers: use decides.** The hour is neither a price rule nor a measure of use. Stays are already metered per
   second, and a stay already ends after 300 s idle (`AGENT_IDLE_TIMEOUT_SECONDS`). The hour is the guest's whole life
   counted from boot, mostly spent waiting for someone. A guest nobody used is thrown away at 60 minutes. One first
   used at minute 50 must stop admitting at minute 52. Separate the three:
   - **Guest lifetime:** until its one stay ends. An unused guest waits as long as it is needed.
   - **Stay length:** ends after disuse (the idle timeout) or when its paid time runs out. It extends in increments
     while used and paid for.
   - **Price:** a minimum charge or an increment size if we want one. It is a billing rule and holds no VM up.

   A guest's registration stays valid while the Mac's heartbeat shows it alive, not until a fixed expiry. It attests only when a browser asks, so the 64 count tracks use, not idle
   time. Today idle guests re-register on a loop and each registration attests, which uses up the 64 in about an hour.
   Admission close and drain go away with the hour. Any bound that matters (stay length, spend) moves onto the stay.
   Needs:
   - a new guest build, since the run limit is measured;
   - its class registered again on each escrow;
   - broker registration without a fixed expiry;
   - a runner that counts per stay, which means a re-signed runner and a new code hash on chain.

   The VM count then follows use exactly: spares plus active stays. Combines with 2: spares on demand first, timers
   removed later.

## What other systems do

CI runners have the same shape as our guests: single use, a boot of a minute or so, and a fixed host budget.
- GitLab's instance and docker-autoscaler executors run one job per instance (`capacity_per_instance=1`,
  `max_use_count=1`) and delete the instance after it. They keep `idle_count` idle instances, each for at least
  `idle_time`, under `max_instances` ([docs](https://docs.gitlab.com/runner/executors/instance.html)). A preemptive
  mode takes a job only when an idle instance is ready, so no job waits for a boot.
- GitHub's runner scale sets (ARC) target `minRunners` plus one runner per assigned job, capped at `maxRunners`
  ([docs](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets)).

Both size the idle floor by hand, independent of the cap. Neither fills every slot ahead of demand, and neither
rotates idle instances on a fixed lifetime.

The research agrees on keeping a floor:
- In queueing models where servers take time to boot, keeping a few servers always on beats turning everything off
  when idle. Gandhi, Harchol-Balter and Adan ([2010](https://www3.cs.stonybrook.edu/~anshul/perf_mmk_2010.pdf)) turn
  an idle server off only above a threshold. Maccio and Down ([acc](https://www.cas.mcmaster.ca/~downd/acc_final.pdf))
  find a floor near the expected number of busy servers close to optimal, while a floor of zero can be far from it.
  So option 3 is the wrong end.
- Serverless platforms keep instances warm after use rather than before it. Shahrad et al.
  ([ATC 2020](https://arxiv.org/pdf/2003.03423)) size the keep-alive window from each application's histogram of idle
  times, and beat fixed 10- and 20-minute windows on cold starts per unit of memory. That is a later refinement for us
  (drop to zero spares overnight) once we have arrival data.

None of these models has single-use guests with a hard lifetime. The recipe below is ours, not theirs.

Agent sandbox platforms keep three things apart: maximum lifetime, release on disuse, and billing.

| | Open source | Isolation | Warm pool | What ends a sandbox |
|---|---|---|---|---|
| [E2B](https://github.com/e2b-dev/infra) | yes, Apache-2.0; one-machine self-host | Firecracker microVM, restored from snapshot | pre-booted snapshots | create/pause/resume/kill API |
| [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) (kubernetes-sigs) | yes | gVisor or Kata via RuntimeClass | `SandboxWarmPool`, fixed `replicas`, scalable by KEDA/HPA | absolute `shutdownTime` or delete; idle suspend only on the roadmap |
| [Modal](https://modal.com/docs/guide/sandbox) | no | | | `idle_timeout` (activity = running command, stdin, open tunnel connection), separate from max `timeout` |
| [Cloudflare Sandbox](https://developers.cloudflare.com/sandbox/api/lifecycle) | no | container | | sleeps after `sleepAfter` idle (10 min default); `keepAlive` heartbeats hold it; `destroy()` |
| [Fly Machines](https://docs.fly.io/about/pricing) | no | Firecracker | | proxy stops or suspends on excess capacity |

Fly bills a running Machine per second, and a stopped one only for its disk. Billing follows run time, not how long
the VM exists. Agent Sandbox's warm-pool example sizes the pool from claim rate × time to replenish one sandbox, the
same rule as our floor.

Nothing about Daytona, microsandbox, OpenHands, Arrakis or Coder survived verification either way.

## Decision

Proposed: option 2, as GitLab and ARC do it.

1. **Cap.** At most `max_guests` guests run, booted or booting. Memory bounds it: (64 − 16) / 4 = 12 on a 64 GB Mac.
2. **Floor.** Keep `spares` idle, admitting guests, set in `operator.json`, default 1. Size it as at least the stays
   that arrive during one boot: ceil(arrivals per minute × 1 min) + 1.
3. **Replace on consume.** When a stay claims a spare, boot one guest at once to restore the floor. Do not wait for it
   to be needed.
4. **Rotate idle spares by remaining lifetime.** Replace an idle spare only when it can no longer take a useful stay:
   5 minutes before its admission closes (`pool.replace_after`), not at half-life.
5. **Release on disuse.** A stay ends after an idle window that resets on activity (a tool call, input, an open
   connection), as Modal and Cloudflare do. The guest is destroyed when its stay ends. Billing is metered run time with
   its own minimum and increments.
6. **Later.** Optionally take a stay only when a spare is ready, and let the floor follow time of day once we have
   arrival data.

Options 4 and 5 are a separate decision once the reasons for the two caps are known. Option 5 is the end state if the
caps protect nothing a per-stay bound cannot. It turns rule 4 into "never".

## Consequences

- One user on the demo costs about 2 VMs instead of 8, and the freed memory can give staging a second slot.
- A burst larger than `spares` waits about a minute per extra guest. The page already shows busy Macs.
- The page's free-slot count shows idle spares, not capacity. It should show both.
- Open: why runs are capped at one hour and 64 attestations. If the caps are arbitrary, option 4 is the larger saving.
