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
5. **No timers.** A guest lives until it serves its one stay. Its registration stays valid while the Mac's heartbeat
   shows it alive, not until a fixed expiry. It attests only when a browser asks, so the 64 count tracks use, not idle
   time. Today idle guests re-register on a loop and each registration attests, which uses up the 64 in about an hour.
   Admission close and drain go away with the hour. Any bound that matters (stay length, spend) moves onto the stay.
   Needs:
   - a new guest build, since the run limit is measured;
   - its class registered again on each escrow;
   - broker registration without a fixed expiry;
   - a runner that counts per stay, which means a re-signed runner and a new code hash on chain.

   The VM count then follows use exactly: spares plus active stays. Combines with 2: spares on demand first, timers
   removed later.

<!-- research: how CI runner autoscalers, serverless warm pools and the literature size idle pools; to be added. -->

## Decision

Proposed: option 2, with `spares` set per Mac in `operator.json` (default 1) and the slot count as the cap.
Replacements of idle spares start 5 minutes before their admission closes (`pool.replace_after`). Options 4 and 5
are a separate decision once the reasons for the two caps are known; 5 is the end state if they protect nothing that
a per-stay bound cannot.

## Consequences

- One user on the demo costs about 2 VMs instead of 8, and the freed memory can give staging a second slot.
- A burst larger than `spares` waits about a minute per extra guest. The page already shows busy Macs.
- The page's free-slot count shows idle spares, not capacity. It should show both.
- Open: why runs are capped at one hour and 64 attestations. If the caps are arbitrary, option 4 is the larger saving.
