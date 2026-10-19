# transfer: getting a seed into a running dispatch

Two ways for the CPU to hand a running GPU kernel a secret-sized input, built
on the same system-scope mailbox.

- **Value channel** (`vc_system`): per exchange the CPU stores 7 fresh words
  plus a checksum word into the mailbox, then a release counter. The GPU checks
  the checksum and folds all 8 words into a register hash,
  `h = (h ^ w) * 16777619`. Both sides compute the hash, so a corrupted
  transfer shows up on either side.
- **Timing channel** (`timing_system`): the CPU only ever stores the constant
  `0xC0FFEE01`. Per symbol the GPU clears the word, signals ready and counts
  spin iterations until the constant appears. The CPU encodes symbol `s` by
  waiting `d0 + s·Δ` before the store. The stored value never varies.

The seeds are public synthetic LCG output. Nothing here is a real key.

## Run

```sh
bash run_value.sh                 # seconds; prints PASS
bash run_timing.sh                # ~10 s; T_iter probes, then the Δ × alphabet sweep
python3 analyze_timing.py out/logs
python3 offline_hash.py out/logs/value/lcg_seed1000.json   # any machine
```

`run_value.sh` runs 1.1 M exchanges with seed 1000 and again with seed 2000.
It passes when each GPU hash matches the CPU's and the two differ.
`run_timing.sh` measures the per-iteration time `T_iter` of the system- and
device-scope spin (`sys_poll`, `dev_poll`), then sweeps Δ ∈ {1, 2, 4, 8} ×
T_iter and alphabets {2, 4, 16} with d0 = 10 µs: a round-robin calibration
dispatch, 10,000 LCG symbols, and a constant-delay control per Δ.
`analyze_timing.py` decodes each run with per-symbol medians from the first
half of the dispatch and tests on the second half.

## Recorded result

Mac mini M4 Pro, macOS 27.0 (26A428), 13–14 October 2026.

Value channel (`results/value/`): seed 1000 → GPU hash 1155756988, seed 2000 →
513356732, both equal to the CPU's and to `offline_hash.py` run on Linux,
at about 1.05–1.09 M exchanges/s with 0 wrong hashes and 0 checksum failures.
An earlier run of the same kernel ran 405 M exchanges at ~1.09 M/s with no
errors (`phaseB-405M-exchanges.txt`); that run used the predecessor host with
the LCG defect described under Provenance.

Timing channel (`results/timing/analysis.txt`, primary run; the replicate
run agrees for Δ ≥ 4×):

| Δ | A | symbol error (CV) | bits/symbol (CV) | symbols/s | bits/s |
|---|---|---|---|---|---|
| 1× (253 ns) | 16 | 0.324 | 3.17 | 73,179 | 231,795 |
| 2× (506 ns) | 16 | 0.055 | 3.75 | 64,448 | 241,461 |
| 4× (1012 ns) | 2 | 0.007 | 0.94 | 81,372 | 76,683 |
| 4× (1012 ns) | 4 | 0.008 | 1.94 | 75,472 | 146,184 |
| 4× (1012 ns) | 16 | 0.012 | 3.89 | 51,734 | 201,230 |
| 8× (2023 ns) | 16 | 0.012 | 3.89 | 36,794 | 143,129 |

`T_iter` was 252.9 ns in system scope and 181.1 ns in device scope
(`titer_*.json`). With Δ ≥ 4 × T_iter, error is about 1% and A = 16 carries
3.89 bits per symbol, so a 256-bit seed needs about 66 symbols, under 2 ms.
The rate is set by d0 = 10 µs; smaller d0 was not tried. Under a constant
delay the count is not deterministic: the mode holds 78–98% of samples, with
rare outliers up to 2097. The first configuration of each run (Δ = 1×, A = 2)
decoded nothing because counts ramp from ~8 to ~35 over the first few
thousand symbols, which fits a GPU clock ramp (not verified).

## Files

| File | Contents |
|---|---|
| `transfer.metal` | `vc_system`/`vc_device` (value), `timing_system`/`timing_device` (timing), `sys_poll`/`dev_poll` (T_iter probes) |
| `transfer2_host.mm` | Value-channel host. `fresh` mode drives `vc_system`; `matched` mode is the no-exchange control used by `../dcs-bandwidth-calibration` |
| `timing_host.mm` | Timing-channel host; writes per-symbol `s, D_ns, count` CSV |
| `run_value.sh`, `run_timing.sh` | Runners |
| `analyze_timing.py` | Symbol error, mutual information and bits/s per configuration |
| `offline_hash.py` | Recomputes the value channel's final hash from the seed |
| `results/` | Value-channel JSONs, timing analysis, T_iter probes, one rng run's JSON, environment |
