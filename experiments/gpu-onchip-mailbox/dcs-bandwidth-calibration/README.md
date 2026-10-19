# dcs-bandwidth-calibration: does the mailbox line get written back?

A mailbox exchange stores to one 128-byte line about a million times a second.
If that line were written back to DRAM on every exchange, the SoC would add
about 140 MB/s of DRAM writes. This experiment asks whether an unprivileged
counter can see 140 MB/s at all (phase 1), and then whether the real exchange
adds anything over a matched control (phase 2).

The counter is IOReport group `PMP`, subgroup `DCS BW`, read without root by
`iomon.m`. Each channel is a 32-state histogram of bandwidth levels, sampled
at roughly 4.1–4.4 kHz while the requester is active: `AMCC RD/WR` (all
requesters, 16 GB/s bins), and per requester `PACC0/1` (performance CPU
clusters), `EACC0` (efficiency cluster) and `AGX` (GPU) in 1 GB/s bins. The
lowest bin is a floor with no zero. `dcs.py` decodes it; the statistic is
above-floor samples per wall-second.

## Run

```sh
bash run_phase1.sh   # ~17 min, CPU only
bash run_phase2.sh   # ~8 min, needs ../transfer
python3 analyze.py phase1 out/logs/phase1/timeline.txt out/logs/phase1/dram_watch.csv.gz
python3 analyze.py phase2 out/logs/phase2/timeline.txt out/logs/phase2/dram_watch.csv.gz out/logs/phase2/rates.log
```

Phase 1: `inject.c` writes sequential 128-byte lines into a 1 GiB buffer,
paced at 35, 70, 140, 280 and 1000 MB/s (plus unpaced), against a `spin`
control that runs the same pacing loop into a 32 KiB L1-resident buffer.
20 blocks in a fixed shuffled order, a 512 MiB read-flush and 1 s settle
between windows. A rate counts as detected on a channel if the paired
difference from `spin` has permutation p < 0.01 and the response is monotone
in rate (p < 0.01). Both rules were fixed before the run.

Phase 2, 20 blocks of:
- **a**: the real exchange, `transfer2_host vc_system fresh`, 4.5 M exchanges;
- **b**: matched control, `transfer2_host dev_poll matched`: the same CPU loop
  and stores into a `malloc`'d line the GPU never maps, advancing every 917 ns,
  while a device-scope kernel spins on its own buffer;
- **c70 / c140**: b plus the phase 1 injector at 70 or 140 MB/s, as positive
  controls that calibrate each channel's slope in-run.

(a) − (b) is converted to MB/s through the (c) slope and divided by 140.6 MB/s
(one 128-byte line per exchange at the measured rate).

The analysis runs anywhere. The raw watch CSVs (about 175 MB gzipped) are not
included; `results/raw-csv-sha256.txt` pins them.

## Recorded result

Mac mini M4 Pro, macOS 27.0 (26A428), 14 October 2026. 160/160 phase 1 and
80/80 phase 2 windows ran; injector rates were exact; phase 2 exchanges ran at
1.085–1.118 M/s with 0 wrong hashes.

Phase 1 (`results/phase1_analysis.txt`), above-floor samples/s, mean of 20:

| channel | spin | 35 | 70 | 140 | 280 | 1000 MB/s | smallest detected |
|---|---|---|---|---|---|---|---|
| AMCC WR | 0.0 | 0.68 | 1.18 | 0.68 | 0.54 | 1.37 | none |
| PACC0+1 WR | 35.2 | 45.9 | 54.5 | 83.1 | 185.7 | 798.0 | 140 MB/s |
| EACC0 WR | 21.5 | 44.0 | 78.1 | 115.6 | 177.8 | 378.4 | 35 MB/s |
| AMCC RD | 2.70 | 2.02 | 2.38 | 1.49 | 2.66 | 2.88 | none |

The total-traffic channels cannot see these rates. The CPU-cluster channels
can.

Phase 2 (`results/phase2_analysis.txt`):

| channel | (a) − (b), mean ± SE | 99% upper bound | (c) slope p, c70 / c140 | bound, MB/s | line writebacks per exchange |
|---|---|---|---|---|---|
| EACC0 WR | +0.15 ± 5.47 | +14.0 | 0.0001 / 0.0001 | 18.9 | ≤ 0.135 |
| PACC0+1 WR | −2.70 ± 8.45 | +18.8 | 0.037 / 0.0055 | 132 | ≤ 0.94 |

The real exchange adds no detectable CPU-cluster write traffic over the
matched control. The bound to quote is the PACC one, **≤ 0.94 writebacks per
exchange at 99%**. The tighter EACC0 bound holds only if the exchange thread
ran on efficiency cores, and a busy-spinning thread probably ran on a
performance cluster (neither thread's QoS or affinity was set; inference from
the review). PACC's calibration is weak: its c70 control missed p < 0.01.

## Files

| File | Contents |
|---|---|
| `inject.c` | Paced line writer, L1 spin control, read-flush |
| `iomon.m` | IOReport channel lister and watcher (prototypes declared in-file; links `-lIOReport`) |
| `run_phase1.sh`, `run_phase2.sh` | Runners with the fixed shuffled orders embedded |
| `dcs.py`, `analyze.py` | Histogram decoder and the phase 1 / phase 2 analysis |
| `results/` | Both analyses, run logs, phase 2 per-window rates, raw CSV hashes |
