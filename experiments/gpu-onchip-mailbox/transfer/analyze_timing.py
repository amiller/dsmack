#!/usr/bin/env python3
# Timing-channel analysis (reanalysis of run_timing.sh output). Per config: the
# worker-style SER (decoder from the separate cal dispatch), cross-validated SER
# (medians from the first half of the rng dispatch, tested on the second half),
# mutual information and bits/s; then the constant-delay control's count spread.
# usage: analyze_timing.py <logs dir holding phaseC/...> [run ...]   (default run: phaseC)
import csv, math, json, re, sys, statistics as st
from collections import defaultdict, Counter
B=sys.argv[1].rstrip('/')+'/'
def rows(p): return [(int(r['s']),int(r['count'])) for r in csv.DictReader(open(p))]
def mi(pairs):
    n=len(pairs); ps=Counter(s for s,_ in pairs); pc=Counter(c for _,c in pairs); j=Counter(pairs)
    return sum(v/n*math.log2((v/n)/((ps[s]/n)*(pc[c]/n))) for (s,c),v in j.items())
def H(xs):
    n=len(xs); return -sum(v/n*math.log2(v/n) for v in Counter(xs).values())
def decoder(train):
    per=defaultdict(list)
    for s,c in train: per[s].append(c)
    med={s:st.median(v) for s,v in per.items()}
    return lambda c: min(med,key=lambda k:abs(c-med[k])), med
def jrate(p):
    return float(re.search(r'"symbols_per_s":([0-9.]+)',open(p).read()).group(1))
for run in sys.argv[2:] or ['phaseC']:
    print('=====',run)
    print('cfg      dNs  n   SERcal  MIcalDec  SERcv  MIcv(dec,test) MIraw(s;count,all) MIraw_test sym/s  bits/s(MIcv)  cal_s0_mean rng_first200_med rng_last_med')
    for dx in (1,2,4,8):
        for a in (2,4,16):
            cal=rows(f'{B}{run}/cal_dx{dx}_a{a}.csv'); rng=rows(f'{B}{run}/rng_dx{dx}_a{a}.csv')
            dec,_=decoder(cal)
            # worker used means not medians; replicate means
            per=defaultdict(list)
            for s,c in cal: per[s].append(c)
            mean={s:sum(v)/len(v) for s,v in per.items()}
            dm=lambda c: min(sorted(mean),key=lambda k:abs(c-mean[k]))
            pw=[(s,dm(c)) for s,c in rng]; serw=sum(s!=h for s,h in pw)/len(pw)
            tr,te=rng[:len(rng)//2],rng[len(rng)//2:]
            d2,med=decoder(tr); pc=[(s,d2(c)) for s,c in te]; sercv=sum(s!=h for s,h in pc)/len(pc)
            rate=jrate(f'{B}{run}/rng_dx{dx}_a{a}.json')
            dns=json.loads(open(f'{B}{run}/rng_dx{dx}_a{a}.json').read().split(' ',1)[1])['delta_ns']
            print(f'dx{dx}_a{a:<3d} {dns:5.0f} {len(rng)} {serw:7.4f} {mi(pw):7.3f}  {sercv:7.4f} {mi(pc):7.3f}        {mi(rng):7.3f}           {mi(te):7.3f}   {rate:7.0f} {mi(pc)*rate:9.0f}   {mean[0]:6.2f}  {st.median(c for _,c in rng[:200]):5.1f} {st.median(c for _,c in rng[-2000:]):5.1f}')
    print('constD (A=16, s=8):')
    for dx in (1,2,4,8):
        cs=[c for _,c in rows(f'{B}{run}/constD_dx{dx}.csv')]
        q=sorted(cs); n=len(q)
        top=Counter(cs).most_common(4)
        print(f'  dx{dx} n={n} mean={st.mean(cs):.2f} sd={st.stdev(cs):.2f} median={q[n//2]} p1={q[n//100]} p99={q[99*n//100]} min={q[0]} max={q[-1]} distinct={len(set(cs))} H={H(cs):.2f} bits top={top} rate={jrate(f"{B}{run}/constD_dx{dx}.json"):.0f}/s')
