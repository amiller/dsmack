#!/usr/bin/env python3
"""analyze.py — phase 1 / phase 2 analysis.

Reads the Mac-produced timeline.txt (<ms> <cond>_start <block> /
<ms> <cond>_end <block>) plus the single iomon watch CSV for the phase
(unix_ms,group,subgroup,channel,state,value; cumulative per-state residency
counts, optionally gzipped) and prints the calibration / detection tables.

Histogram decoding follows the pinned reanalysis decoder
dcs.py (32 states per channel, level labels in
GB/s, cumulative counts -> per-interval deltas, lowest state is a floor bin,
no zero bin). dcs.py is imported for its level parser (dcs.LV) and delta
semantics; intervals are accumulated in one streaming pass so a 26-minute
100 ms watch stays memory-bounded.

Per window, only sampler intervals fully inside [start+1 s, end-0.1 s] are
used. Primary statistic: above-floor samples per wall-second (the sample rate
is activity-gated, so a plain fraction is biased). Secondary:
sum((level-floor) x events) / wall seconds, reported as MB/s.

Usage:
  analyze.py phase1 <timeline.txt> <dram_watch.csv[.gz]> [<rates.log>]
  analyze.py phase2 <timeline.txt> <dram_watch.csv[.gz]> <rates.log> \
      [--groups AMCC_WR,PACC_WR]
"""
import csv
import gzip
import math
import os
import random
import re
import sys
from statistics import mean, stdev

import dcs  # the decoder next to this file
DCS_PATH = os.path.basename(dcs.__file__)

# Channel groups. Primary named targets first (task-specified), then
# informational. PACC0+PACC1 WR are summed because the injector thread
# migrates between P clusters.
GROUPS = [
    ('AMCC_WR',  ['AMCC WR']),
    ('PACC_WR',  ['PACC0 WR', 'PACC1 WR']),
    ('EACC0_WR', ['EACC0 WR']),
    ('AMCC_RD',  ['AMCC RD']),
    ('EACC0_RD', ['EACC0 RD']),
    ('PACC_RD',  ['PACC0 RD', 'PACC1 RD']),
]
ALL_CHAN = sorted({c for _, ms in GROUPS for c in ms})

# One-sided 99% t quantiles (upper 1%).
T99 = {1: 3.078, 2: 6.965, 3: 4.541, 4: 3.747, 5: 3.365, 6: 3.143, 7: 2.998,
       8: 2.896, 9: 2.821, 10: 2.764, 11: 2.718, 12: 2.681, 13: 2.650,
       14: 2.624, 15: 2.602, 16: 2.583, 17: 2.567, 18: 2.552,
       19: 2.539, 20: 2.528, 21: 2.518, 22: 2.508, 23: 2.500, 24: 2.492,
       25: 2.485, 26: 2.479, 27: 2.473, 28: 2.467, 29: 2.462, 30: 2.457,
       40: 2.423, 60: 2.390, 120: 2.358}

NPERM = 10000

# ------------------------------------------------------------------ loaders
def load_timeline(path):
    """-> list of (ms, event, block_or_None)"""
    out = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                ms = int(parts[0])
            except ValueError:
                continue
            ev = parts[1]
            blk = None
            m = re.match(r'^(.*)_(start|end)$', ev)
            if m:
                ev = m.group(1) + '_' + m.group(2)
            if len(parts) >= 3:
                try:
                    blk = int(parts[2])
                except ValueError:
                    blk = None
            out.append((ms, ev, blk))
    return out

def windows_from_timeline(tl):
    """-> {(cond, block): (start_ms, end_ms)}"""
    open_w = {}
    win = {}
    for ms, ev, blk in tl:
        m = re.match(r'^(.*)_(start|end)$', ev)
        if not m:
            continue
        cond, edge = m.group(1), m.group(2)
        if cond in ('block', 'phase'):
            continue
        if edge == 'start':
            open_w[(cond, blk)] = ms
        else:
            s = open_w.pop((cond, blk), None)
            if s is not None:
                win[(cond, blk)] = (s, ms)
    return win

def stream_intervals(path, chans):
    """One pass over the iomon CSV.
    -> {chan: [(t_a, t_b, above, total, excess_GB_events), ...]}
    Interval (t_a, t_b] delta per level = cum(t_b) - cum(t_a); floor is the
    lowest level label seen on the channel (a floor bin, not zero).
    """
    opener = gzip.open if str(path).endswith('.gz') else open
    ivl = {c: [] for c in chans}
    prev_t, prev_cum = None, None
    cur_t, cur_cum = None, None
    nrow = 0
    with opener(path, 'rt') as f:
        for r in csv.reader(f):
            if not r or len(r) < 6 or r[0] == 'unix_ms':
                continue
            try:
                t = int(r[0])
                v = int(r[5])
            except ValueError:
                continue
            ch = r[3]
            if ch not in chans:
                continue
            m = dcs.LV.search(r[4])
            if not m:
                continue
            lv = float(m.group(1))
            nrow += 1
            if t != cur_t:
                if prev_t is not None and cur_t is not None:
                    for c in chans:
                        pc, cc = prev_cum.get(c), cur_cum.get(c)
                        if not pc or not cc:
                            continue
                        lvset = set(pc) | set(cc)
                        floor = min(lvset)
                        tot = ab = 0
                        ex = 0.0
                        for l in lvset:
                            dd = cc.get(l, 0) - pc.get(l, 0)
                            if dd <= 0:
                                continue
                            tot += dd
                            if l > floor:
                                ab += dd
                                ex += (l - floor) * dd
                        ivl[c].append((prev_t, cur_t, ab, tot, ex))
                prev_t, prev_cum = cur_t, cur_cum
                cur_t, cur_cum = t, {c: {} for c in chans}
            cur_cum[ch][lv] = v
    sys.stderr.write('analyze: %d state rows parsed from %s\n' % (nrow, path))
    return ivl

# ------------------------------------------------------------ window stats
def window_stat(ivl, members, s_ms, e_ms, trim_head_ms=1000, trim_tail_ms=100):
    lo, hi = s_ms + trim_head_ms, e_ms - trim_tail_ms
    above = tot = 0
    ex = 0.0
    first = last = None
    for ch in members:
        for (a, b, ab, tt, ee) in ivl.get(ch, ()):
            if a >= lo and b <= hi:
                above += ab
                tot += tt
                ex += ee
                if first is None or a < first:
                    first = a
                if last is None or b > last:
                    last = b
    if first is None or last is None or last <= first:
        return None
    wall = (last - first) / 1000.0
    return dict(above=above, total=tot, excess=ex, wall=wall,
                above_ps=above / wall, excess_mbps=1000.0 * ex / wall)

def compute_window_stats(ivl, wins):
    """-> {(group, cond, block): stat dict}"""
    st = {}
    for gname, members in GROUPS:
        for (cond, blk), (s, e) in wins.items():
            r = window_stat(ivl, members, s, e)
            if r is not None:
                st[(gname, cond, blk)] = r
    return st

# ----------------------------------------------------------------- tests
def sign_flip_p(diffs, nperm=NPERM, seed=20261015):
    """One-sided sign-flip permutation test that mean(diffs) > 0."""
    d = list(diffs)
    if len(d) < 2:
        return float('nan'), mean(d) if d else float('nan')
    obs = mean(d)
    rng = random.Random(seed)
    cnt = 0
    for _ in range(nperm):
        m = 0.0
        for x in d:
            m += x if rng.random() < 0.5 else -x
        if m / len(d) >= obs:
            cnt += 1
    return (1 + cnt) / (nperm + 1), obs

def trend_p(vecs, weights, nperm=NPERM, seed=20261016):
    """Permutation test for a monotone (weighted-in-log-rate) increasing
    effect. vecs: per-block list of [d_r0, d_r1, ...] aligned to weights.
    Null: permute the condition labels independently within each block."""
    k = len(weights)
    nb = len(vecs)
    means = [mean(v[i] for v in vecs) for i in range(k)]
    obs = sum(w * m for w, m in zip(weights, means))
    rng = random.Random(seed)
    cnt = 0
    for _ in range(nperm):
        pm = [0.0] * k
        for v in vecs:
            pv = v[:]
            rng.shuffle(pv)
            for i in range(k):
                pm[i] += pv[i]
        S = sum(w * (x / nb) for w, x in zip(weights, pm))
        if S >= obs:
            cnt += 1
    return (1 + cnt) / (nperm + 1), obs

def t99(df):
    if df in T99:
        return T99[df]
    if df > 120:
        return 2.326
    # interpolate on 1/df
    ks = sorted(k for k in T99 if k < 200)
    lo = max(k for k in ks if k <= df)
    hi = min(k for k in ks if k >= df)
    if lo == hi:
        return T99[lo]
    w = (1.0 / df - 1.0 / lo) / (1.0 / hi - 1.0 / lo)
    return T99[lo] * (1 - w) + T99[hi] * w

def fmt(x, nd=3):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return '--'
    return ('%.' + str(nd) + 'f') % x

# ----------------------------------------------------------------- phase 1
RATES = ['r0', 'r35', 'r70', 'r140', 'r280', 'r1000']
TREND_RATES = ['r70', 'r140', 'r280', 'r1000']
TREND_W = [1, 2, 3, 4]

def phase1(timeline_path, csv_path):
    tl = load_timeline(timeline_path)
    wins = windows_from_timeline(tl)
    ivl = stream_intervals(csv_path, ALL_CHAN)
    st = compute_window_stats(ivl, wins)

    conds = sorted({c for (_, c, _) in st})
    print('=== Phase 1 analysis ===')
    print('dcs.py: %s' % DCS_PATH)
    print('windows parsed: %d  conditions: %s' % (len(wins), conds))
    nblk = len({b for (_, _, b) in st})
    print('blocks with any window: %d' % nblk)

    # sanity: implied AMCC WR sample rate over the whole watch
    tot_ev = sum(v[3] for v in ivl.get('AMCC WR', ()))
    span = 0.0
    iv = ivl.get('AMCC WR', ())
    if len(iv) > 1:
        span = (iv[-1][1] - iv[0][0]) / 1000.0
    if span > 0:
        print('AMCC WR events/s over watch: %.1f (%d events / %.1f s)'
              % (tot_ev / span, tot_ev, span))

    # per-condition table
    for gname, _ in GROUPS:
        print('\n--- %s : per-condition means (window counts n) ---' % gname)
        print('cond      n   above_ps mean±SE      excess MB/s mean±SE')
        for cond in RATES + ['spin', 'idle']:
            vals = [st[k] for k in st if k[0] == gname and k[1] == cond]
            if not vals:
                continue
            a = [v['above_ps'] for v in vals]
            e = [v['excess_mbps'] for v in vals]
            se_a = stdev(a) / math.sqrt(len(a)) if len(a) > 1 else float('nan')
            se_e = stdev(e) / math.sqrt(len(e)) if len(e) > 1 else float('nan')
            print('%-6s %4d  %9.2f ± %-8.2f %10.1f ± %-8.1f'
                  % (cond, len(a), mean(a), se_a, mean(e), se_e))

    # paired detection: injector rate - spin, paired by block
    print('\n--- paired detection vs spin (statistic: above-floor samples per'
          ' wall-second) ---')
    gate = {}
    for gname, _ in GROUPS:
        print('\n%s:' % gname)
        print('rate   n_pairs  mean diff   perm p     detected(p<0.01 and trend)')
        spin_by_blk = {k[2]: st[k]['above_ps'] for k in st
                       if k[0] == gname and k[1] == 'spin'}
        diffs_by_rate = {}
        for rate in RATES:
            d = []
            for (gn, cond, blk), v in st.items():
                if gn != gname or cond != rate or blk not in spin_by_blk:
                    continue
                d.append(v['above_ps'] - spin_by_blk[blk])
            diffs_by_rate[rate] = d
        # trend over 70..1000 (blocks with all four rates and spin)
        vecs = []
        for blk in sorted(spin_by_blk):
            row = []
            ok = True
            for rate in TREND_RATES:
                v = [st[(gname, rate, blk2)]['above_ps']
                     for blk2 in [blk] if (gname, rate, blk2) in st]
                if not v:
                    ok = False
                    break
                row.append(v[0] - spin_by_blk[blk])
            if ok:
                vecs.append(row)
        p_trend, S_obs = (float('nan'), float('nan'))
        if len(vecs) >= 2:
            p_trend, S_obs = trend_p(vecs, TREND_W)
        print('trend test (70->1000, log-rate weights): blocks=%d S=%.3f p=%.4f'
              % (len(vecs), S_obs if not math.isnan(S_obs) else 0, p_trend))
        smallest = None
        for rate in RATES:
            d = diffs_by_rate[rate]
            if len(d) < 2:
                print('%-6s %4d      --         --          --' % (rate, len(d)))
                continue
            p, md = sign_flip_p(d)
            det = (p < 0.01 and not math.isnan(p_trend) and p_trend < 0.01
                   and md > 0)
            print('%-6s %4d  %9.3f  %8.4f    %s'
                  % (rate, len(d), md, p, 'YES' if det else 'no'))
            if det and (smallest is None):
                smallest = rate
        gate[gname] = dict(
            smallest=smallest, p_trend=p_trend,
            det140=(len(diffs_by_rate.get('r140', [])) >= 2
                    and sign_flip_p(diffs_by_rate['r140'])[0] < 0.01
                    and not math.isnan(p_trend) and p_trend < 0.01
                    and mean(diffs_by_rate['r140']) > 0))
        print('smallest detected rate: %s' % (smallest or 'none'))

    print('\n--- GATE ---')
    primary = ['AMCC_WR', 'PACC_WR', 'EACC0_WR', 'AMCC_RD']
    det_any = [g for g in primary if gate.get(g, {}).get('det140')]
    print('channels detecting 140 MB/s: %s' % (det_any or 'NONE'))
    if not det_any:
        print('GATE FAILED: no channel detects 140 MB/s -> the unprivileged '
              'DCS BW path cannot answer the mailbox question; skip phase 2.')
    else:
        only_pacc = (set(det_any) <= {'PACC_WR', 'PACC_RD'})
        print('GATE PASSED via %s%s' % (det_any,
              ' (only PACC: bounds CPU-attributed traffic only)' if only_pacc else ''))
    return gate

# ----------------------------------------------------------------- phase 2
def phase2(timeline_path, csv_path, rates_log, groups=None):
    tl = load_timeline(timeline_path)
    wins = windows_from_timeline(tl)
    ivl = stream_intervals(csv_path, ALL_CHAN)
    st = compute_window_stats(ivl, wins)
    gnames = groups or ['AMCC_WR', 'PACC_WR', 'EACC0_WR', 'AMCC_RD']

    # measured exchange rate from rates.log EXCH lines
    exch = []
    try:
        with open(rates_log) as f:
            for line in f:
                m = re.search(r'EXCH block=\d+ cond=a\b.*trips_per_s=([\d.]+)', line)
                if m:
                    exch.append(float(m.group(1)))
    except OSError:
        pass
    exch_rate = mean(exch) if exch else 1.09e6
    mbps_per_wb = exch_rate * 128.0 / 1e6
    print('=== Phase 2 analysis ===')
    print('dcs.py: %s' % DCS_PATH)
    print('windows parsed: %d' % len(wins))
    print('measured exchange rate: %s trips/s (n=%d) -> one 128 B writeback'
          ' per exchange = %.1f MB/s'
          % (('%.0f' % exch_rate) if exch else 'prior 1.09e6 (fallback)',
             len(exch), mbps_per_wb))

    conds = ['a', 'b', 'c70', 'c140', 'idle']
    for gname in gnames:
        members = dict(GROUPS)[gname]
        print('\n--- %s : per-condition means ---' % gname)
        print('cond    n   above_ps mean±SE      excess MB/s mean±SE')
        for cond in conds:
            vals = [st[k] for k in st if k[0] == gname and k[1] == cond]
            if not vals:
                continue
            a = [v['above_ps'] for v in vals]
            e = [v['excess_mbps'] for v in vals]
            se_a = stdev(a) / math.sqrt(len(a)) if len(a) > 1 else float('nan')
            se_e = stdev(e) / math.sqrt(len(e)) if len(e) > 1 else float('nan')
            print('%-6s %4d  %9.2f ± %-8.2f %10.1f ± %-8.1f'
                  % (cond, len(a), mean(a), se_a, mean(e), se_e))

        for statkey, label in (('above_ps', 'above-floor samples/wall-s'),
                               ('excess_mbps', 'excess MB/s')):
            b_by = {k[2]: st[k][statkey] for k in st
                    if k[0] == gname and k[1] == 'b'}
            a_by = {k[2]: st[k][statkey] for k in st
                    if k[0] == gname and k[1] == 'a'}
            c70 = {k[2]: st[k][statkey] for k in st
                   if k[0] == gname and k[1] == 'c70'}
            c140 = {k[2]: st[k][statkey] for k in st
                    if k[0] == gname and k[1] == 'c140'}
            blocks = sorted(set(a_by) & set(b_by))
            d = [a_by[x] - b_by[x] for x in blocks]
            print('\n%s, statistic %s:' % (gname, label))
            if len(d) < 2:
                print('  insufficient paired windows (n=%d)' % len(d))
                continue
            md, sd = mean(d), stdev(d)
            se = sd / math.sqrt(len(d))
            ub = md + t99(len(d) - 1) * se
            print('  (a)-(b): n=%d mean=%+.4f SE=%.4f  99%% upper bound=%+.4f'
                  % (len(d), md, se, ub))
            # slope from positive controls (c140 - c70)/70 MB/s
            eb = [c140[x] - c70[x] for x in sorted(set(c70) & set(c140))]
            if len(eb) >= 2 and mean(eb) > 0:
                slope = mean(eb) / 70.0
                slope_se = (stdev(eb) / math.sqrt(len(eb))) / 70.0
                p70, _ = sign_flip_p([c70[x] - b_by[x] for x in
                                      sorted(set(c70) & set(b_by))])
                p140, _ = sign_flip_p([c140[x] - b_by[x] for x in
                                       sorted(set(c140) & set(b_by))])
                print('  (c) slope: %.6g per MB/s (SE %.3g); control detection'
                      ' p(c70>b)=%.4f p(c140>b)=%.4f'
                      % (slope, slope_se, p70, p140))
                if slope > 0:
                    ub_mbps = ub / slope
                    wb = ub_mbps / mbps_per_wb
                    print('  (a)-(b) as MB/s via slope: 99%% upper bound ='
                          ' %.2f MB/s' % ub_mbps)
                    print('  -> at most %.4f / %.1f = %.4f line-writebacks per'
                          ' exchange' % (ub_mbps, mbps_per_wb, wb))
                    print('     (writebacks rarer than this bound are not'
                          ' excluded)')
                else:
                    print('  slope <= 0: MB/s bound not computable')
            else:
                print('  no usable (c) slope (mean c140-c70 = %s)'
                      % (fmt(mean(eb)) if eb else 'n/a'))

def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    if mode == 'phase1':
        phase1(sys.argv[2], sys.argv[3])
        return 0
    if mode == 'phase2':
        groups = None
        args = [a for a in sys.argv[4:]]
        if '--groups' in sys.argv:
            i = sys.argv.index('--groups')
            groups = sys.argv[i + 1].split(',')
            args = [a for j, a in enumerate(sys.argv[4:])
                    if j + 4 not in (i, i + 1)]
        rates = args[0] if args else 'rates.log'
        phase2(sys.argv[2], sys.argv[3], rates, groups)
        return 0
    print('unknown mode %s' % mode)
    return 2

if __name__ == '__main__':
    sys.exit(main())
