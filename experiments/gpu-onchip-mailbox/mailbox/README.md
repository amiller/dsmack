# mailbox: CPU↔GPU round trips into one running dispatch

A single-thread GPU kernel advances a 64-bit LCG in a register, publishes the
low 32 bits and a trip counter through a `coherent(system)` shared buffer, and
spins (capped at 2^22 iterations) until the CPU echoes `(val ^ 0xA5A5A5A5) + i`.
The CPU checks each value against its own LCG. A device-scope twin of the
kernel is the negative control.

## Run

```sh
bash run_phaseB.sh && python3 check_phaseB.py out/logs/phaseB   # ~2 min, prints PASS
bash run_phaseC.sh default                                       # ~11 min: 0.5, 5, 50, 590 s dispatches
MLX=<mlx clone> APPLEGPU=<applegpu clone> bash static/run_phaseA.sh   # optional, compile only
```

`check_phaseB.py` checks the output of a fresh run. `results/phaseB/` keeps only the first chunk per configuration plus the summary, so the checker reports FAIL on it.


`run_phaseB.sh` builds `mailbox.metallib` and `mailbox_host`, then runs 10
chunks of 1000 trips for each of: system scope with plain seq_cst CPU atomics
(as MLX does), system scope plus `DSB SY` after the CPU stores, and both again
in device scope. `check_phaseB.py` passes when every system-scope chunk
completes with no wrong value or command-buffer error and every device-scope
chunk cap-hits on trip 1. Each dispatch runs under `../common/wd.sh` (30 s).
Logs go to `out/` (or `$ROOT`).

`run_phaseC.sh` reuses the phase B build and runs one dispatch per step
T = 1, 10, 60, 600 s. The CPU answers for T/2 (T ≤ 10) or T − 10 s, then sets
the stop word; the kernel should exit with `stopped_in_spin`.

`static/run_phaseA.sh` compiles MLX's `fence.metal` (ml-explore/mlx
`243bdf09c0cccbb85ca6a686dab3cc0102cf1f7e`) and `static/control_fence_device.metal`
to LLVM IR, AIR and G16 machine code (via applegpu
`28dd80468d4a6c94fa4dac34ed488196f5fedc5f` `compiler_explorer_tools`), and
diffs them. Those kernels contain `while (1)` and are never dispatched.

## Recorded result

Mac mini M4 Pro, macOS 27.0 (26A428), Apple metal 32023.921, 13 October 2026.

Phase B (`results/phaseB/summary.json`, `all_chunks.txt`):

| config | trips | kernel status | wrong values (GPU/CPU) | CB errors | latency p50 / p99 / p99.9 |
|---|---|---|---|---|---|
| sys_default | 10,000 | done ×10 | 0 / 0 | 0 | 2.50 / 2.63 / 19.0 µs |
| sys_dsbsy | 10,000 | done ×10 | 0 / 0 | 0 | 2.50 / 2.63 / 15.5 µs |
| dev_default | 0 | cap_hit ×10 | 0 / 0 | 0 | (GPU spins to cap, ~0.94 s) |
| dev_dsbsy | 0 | cap_hit ×10 | 0 / 0 | 0 | (same) |

Latency is CPU wall time per full round trip. The 10 samples above 1 ms per
config are the first trip of each chunk (dispatch launch, ~2.3 ms). A rerun
the same evening (`results/retest-results.tsv`) passed.

Phase C (`results/phaseC/console.log`, `step_600.json`):

| T | GPU dispatch | round trips | wrong | kernel status | command buffer |
|---|---|---|---|---|---|
| 1 s | 0.509 s | 720,895 | 0 | stopped_in_spin | completed |
| 10 s | 5.008 s | 7,405,567 | 0 | stopped_in_spin | completed |
| 60 s | 50.019 s | 72,941,567 | 0 | stopped_in_spin | completed |
| 600 s | 590.017 s | 862,715,903 | 0 | stopped_in_spin | completed |

`cpu_lost_wakeup: 1` in these JSONs is the designed stop, not a failure.

Phase A (`results/ir-system-vs-device.diff`): the two variants differ only in
the fence scope operand, `air.atomic.fence(i32 1, i32 5, i32 3)` versus
`i32 2`, and in `air.load/store.system_coherent` versus `device_coherent`. In
G16 machine code `fence_wait` differs in one bit (0x08) of the 16-bit words at
0x40 and 0x50 (`c003` versus `c803`). applegpu targets G13 and cannot decode
these instructions, so the instruction is not named.

## Files

| File | Contents |
|---|---|
| `mailbox.metal` | `mailbox_system` (MLX mechanism) and `mailbox_device` (control); capped spins |
| `mailbox_host.mm` | Loads the metallib, dispatches 1×1 threadgroup, answers trips through `std::atomic_uint` on `MTLBuffer.contents`, prints JSON. Exit 87 on a wedge or command-buffer error |
| `run_phaseB.sh`, `run_phaseC.sh` | Round trips with controls; dispatch lifetime |
| `check_phaseB.py` | PASS/FAIL over phase B output |
| `static/` | IR and machine-code diff of MLX `fence.metal` against a device-scope copy |
| `results/` | Environment, device record, phase B summary and one chunk JSON per config, phase C console and 600 s JSON, IR diff, sha256 of inputs and compiled metallibs, retest verdict |
