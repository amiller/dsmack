# GPU on-chip mailbox

## Question

Can a CPU and a long-running GPU dispatch exchange data through a mailbox, so
that a computation's working set stays in the GPU's on-chip state? And what
bounds how often the mailbox itself gets written back to DRAM?

## Answer

The exchange works on a stock Mac mini M4 Pro, macOS 27.0 (26A428), through an
undocumented memory scope that Apple's MLX uses: 862.7 M round trips in one
590 s dispatch with no errors, about 2.5 µs per round trip. The documented
device scope never sees the CPU's writes. A seed can also be delivered as
write timing, at 3.89 bits per symbol. Against a matched control, the exchange
adds no detectable CPU-attributed DRAM writes: at most 0.94 line writebacks
per exchange (99%, weakly calibrated). That does not show the line never
reaches DRAM, and GPU-attributed traffic, register spills and preemption are
not bounded.

## Guides

A step toward private computation on the GPU: a sealed-bid auction that keeps
its key and the decrypted bids inside one GPU dispatch, so the DRAM bus carries
only public keys, ciphertexts and the result. This PoC tests four assumptions
that design needs: messaging between CPU and GPU, how long a dispatch can live,
part of seed delivery, and part of mailbox writeback. The
threat model is a DRAM observer with an honest host; a malicious host is out
of scope.

## How it works

Three experiments, one per subdirectory:

| Directory | Shows |
|---|---|
| [mailbox/](mailbox/) | Round trips into one running dispatch; device-scope control; dispatches up to 590 s; IR and machine-code diff of the two scopes |
| [transfer/](transfer/) | Seed delivery as stored values, and as write timing with a constant value |
| [dcs-bandwidth-calibration/](dcs-bandwidth-calibration/) | Unprivileged DRAM counter calibration, then real exchange versus a matched control |

### Using the GPU this way

Metal has no API for talking to a kernel while it runs. Command buffers are
submitted, then they finish. The way in is a shared buffer that both sides
poll, with a memory scope that makes CPU stores visible to the running GPU
thread. Apple's MLX does this in `mlx/backend/metal/kernels/fence.metal`
(added in ml-explore/mlx#1773, behind `MLX_METAL_FAST_SYNCH=1`); the kernels
here copy its mechanism and add bounds.

1. **Turn on the internal scope (undocumented).** In the shader:

   ```metal
   #pragma METAL internals : enable
   #ifndef __METAL_MEMORY_SCOPE_SYSTEM__
   #define __METAL_MEMORY_SCOPE_SYSTEM__ 3
   #endif
   namespace metal {
   constexpr constant metal::thread_scope thread_scope_system =
       static_cast<thread_scope>(__METAL_MEMORY_SCOPE_SYSTEM__);
   }
   ```

   The Metal Shading Language spec (4.1) lists thread, simdgroup, threadgroup
   and device scopes only. Scope 3 and the `coherent(system)` qualifier come
   from MLX. The stock toolchain (metal 32023.921) compiles them to
   `air.atomic.fence(i32 1, i32 5, i32 3)` and
   `air.load/store.system_coherent.*`, where device scope gives `i32 2` and
   `device_coherent`.

2. **Declare the mailbox `volatile coherent(system) device uint*`** and
   bracket every access with
   `atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, thread_scope_system)`.
   To publish: store the payload, store the sequence number, fence. To wait:
   fence, load the CPU's response word, compare, repeat.

3. **On the CPU, allocate the buffer with `MTLStorageModeShared`** and cast
   `contents` to `std::atomic_uint*`. Use seq_cst loads and stores, as MLX
   does. Adding `DSB SY` after the stores, which third parties proposed in MLX
   issue #3142, made no difference here.

4. **Dispatch one threadgroup of one thread**
   (`dispatchThreadgroups:{1,1,1} threadsPerThreadgroup:{1,1,1}`), commit,
   and keep answering from the CPU while the command buffer is in flight.
   End the dispatch by writing a stop word, then wait for the command buffer
   to complete.

5. **Keep the working set in kernel locals.** Values the kernel holds in
   thread-local variables, such as `mailbox.metal`'s LCG state `x` or
   `transfer.metal`'s fold hash `h`, never pass through the shared buffer. Only
   the words the protocol publishes do. Whether the compiler keeps those
   locals in registers (no spills to device memory) has not been checked.

6. **Bound every spin.** MLX's `fence_wait` is `while (1)`, and MLX's docs
   warn the fast path "can lead to deadlock and leave the GPU wedged". Every
   loop here has an iteration cap (2^22), the kernel reports its exit status
   in the mailbox, the host exits 87 on a wedge or command-buffer error, and
   `common/wd.sh` kills the host at a fixed bound.

7. **Check both sides.** Each side derives every value from a public seed, so
   a lost or corrupted message is counted by whichever side sees it. Run the
   device-scope twin of each kernel as a control: it must fail.

The mailbox word layouts are in the header comments of `mailbox.metal` and
`transfer.metal`.

### What is documented and what is not

| Part | Status |
|---|---|
| Shared-storage buffers, compute dispatch, command-buffer status | Documented |
| `coherent(device)`, `thread_scope_device`, seq_cst fences | Documented (MSL spec) |
| `MTLCommandBufferError` `timeout` and `accessRevoked` | Documented, with no duration given |
| `#pragma METAL internals`, scope 3, `coherent(system)` | Undocumented. Shipped in Apple's MLX, which calls the path "not reliable" |
| CPU stores becoming visible to a running dispatch | Empirical: M4 Pro, macOS 27.0 (26A428) only |
| A dispatch running for 590 s without a timeout | Empirical, same machine |
| Timing channel symbol rates | Empirical; depend on GPU clock state |
| IOReport (`libIOReport.tbd` ships with no header) and the `DCS BW` bin meanings, sample rate and requester attribution | Undocumented; inferred from calibration |
| G16 instruction encoding of the system-scope fence | Unknown; differs in one bit, not decoded |

Any OS or toolchain update can change the undocumented parts. Rerun
`mailbox/run_phaseB.sh` and `check_phaseB.py` after one.

## Run

Apple silicon Mac with the Xcode command line tools (`xcrun metal`,
`clang++`). Measured only on an M4 Pro under macOS 27.0. MLX enables the same
path on macOS 15+ with Metal 3.2. Run one GPU experiment at a time.

```sh
cd mailbox && bash run_phaseB.sh && python3 check_phaseB.py out/logs/phaseB
```

That is the conformance check: about two minutes, prints `PASS`. The other
runners are listed in each subdirectory's README. Outputs go to `out/` beside
each script, or to `$ROOT`. The analysis scripts (`analyze_timing.py`,
`offline_hash.py`, `analyze.py`, `check_phaseB.py`) run anywhere with
Python 3.

## Recorded result

Mac mini M4 Pro (Mac16,11), macOS 27.0 (26A428), Apple metal 32023.921,
Apple clang 21.0.0, 13–14 October 2026.

| Experiment | Result |
|---|---|
| Mailbox round trips | 10,000 per system-scope config, 0 wrong values, p50 2.50 µs; device scope cap-hit on trip 1 in 20/20 chunks |
| Dispatch lifetime | 0.5, 5, 50 and 590 s dispatches completed; 862,715,903 round trips in the longest, 0 errors |
| Value channel | 1.1 M exchanges per seed at 1.05–1.09 M/s; GPU hash equals CPU and offline recomputation |
| Timing channel | Δ = 4 × T_iter (1012 ns), 16 symbols: 1.2% error, 3.89 bits/symbol, 201 kbit/s |
| Counter sensitivity | CPU-cluster write channels detect 140 MB/s (PACC) and 35 MB/s (EACC0); total-traffic channels detect nothing up to 1000 MB/s |
| Mailbox writeback | (a) − (b) ≈ 0 on every channel; ≤ 0.94 CPU-attributed 128-byte writebacks per exchange (99%) |

Each subdirectory's README has the tables, and its `results/` holds the
summaries, one raw JSON per condition, environments and checksums. On
15 October 2026, on Linux, `analyze.py` reproduced both calibration analyses
from the raw CSVs (identical apart from file paths, CSV hashes matching),
`analyze_timing.py` reproduced the timing analysis exactly, `offline_hash.py`
matched both recorded GPU hashes, and `check_phaseB.py` returned PASS on the
original and retest logs. No Mac-side script was rerun for this PoC.

## Files

| Path | Contents |
|---|---|
| `common/wd.sh` | Parent watchdog: TERM at the bound, KILL one second later, propagate exit status |
| `mailbox/` | `mailbox.metal`, `mailbox_host.mm`, runners, verdict script, `static/` IR diff |
| `transfer/` | `transfer.metal`, `transfer2_host.mm`, `timing_host.mm`, runners, analysis |
| `dcs-bandwidth-calibration/` | `inject.c`, `iomon.m`, runners, `dcs.py`, `analyze.py` |
| `*/results/` | Recorded outcomes (see each README) |

## Provenance

Original sources, evidence and write-ups are in the maintainer's private research archive. The transfer task's
`transfer_host.mm` had an LCG defect (words came from the low 32 bits of the
state, so the seed never changed them); `transfer/transfer2_host.mm` is the
calibration task's fix.

Changes for this PoC: directories flattened and Mac home paths replaced by
script-relative paths (`$ROOT` defaults to `./out`); `static/run_phaseA.sh`
takes `MLX` and `APPLEGPU` clone paths; the timing runner builds its own
metallib, drops the DRAM sampler (its data was uninformative) and narrows its
preflight process match so it does not match its own path; `analyze.py`
imports `dcs.py` from its own directory instead of searching a worker path;
`analyze_timing.py` is the reanalysis `c.py` with the log directory as an
argument; `check_phaseB.py` is the verdict from `retest_phaseB.sh`, whose SSH
wrapper is omitted; `run_value.sh` and `offline_hash.py` are new, built from
`run_phase2.sh` and the reanalysis `rh.py`. Hostnames and home paths in
recorded logs are replaced by `<mac-host>` and `<research-dir>`.

Left out: mailbox phase D (an applegpu special-register sweep, whose
G13-targeted test archive hung the G16 GPU); the transfer task's counter
discovery phase, superseded by the calibration; the defective
`transfer_host.mm`; and the `g16-*` experiments in the same evidence
directory, which are static traces of the kernel driver and firmware rather
than GPU computation.

## Limits

- One machine, one OS build, one day. The mechanism is undocumented and may
  change with any update. M1–M3 and M5 were not tested, though MLX ships the
  same path for all of them.
- Not established: entropy, confidentiality or a protected bootstrap. The
  seeds are public synthetic values.
- The writeback bound covers CPU-cluster-attributed traffic only, at one
  writeback per exchange or more often. GPU-attributed (AGX) traffic is
  uncalibrated, writebacks every Nth exchange or while idle are not excluded,
  and which requester an SLC eviction is charged to is unknown. The exchange
  and injector threads were not pinned to a cluster.
- Register spills (A5) were not checked: no public decoder handles G16, and
  on M3 and later Dynamic Caching may make spilling a run-time decision
  (inference from Apple's description, untested).
- Preemption (A6) was not tested. If the dispatch is context-switched, its
  registers are saved somewhere unknown, possibly DRAM in plaintext.
- Round-trip latency is measured on the CPU side only. The timing channel's
  counts depend on GPU clock state and were not measured under other GPU load.
- `mailbox.metal` derives values from the low 32 bits of the LCG, the same
  defect as `transfer_host.mm`, so its per-chunk seeds did not vary the words.
  This does not affect its pass/fail checks.
- `mailbox/static/` needs MLX and applegpu clones. applegpu targets G13, so
  its disassembler fails on G16 and the binary diff is the authoritative
  comparison.
