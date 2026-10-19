import csv, re, sys
from collections import defaultdict
LV = re.compile(r"([\d.]+)\s*GB/s")
def load(path, chans=None):
    d = defaultdict(lambda: defaultdict(dict))  # ch -> t -> level -> v
    with open(path) as f:
        for r in csv.reader(f):
            if not r or r[0]=='unix_ms': continue
            t,g,sg,ch,st,v = r
            if chans and ch not in chans: continue
            d[ch][int(t)][float(LV.search(st).group(1))] = int(v)
    return d
def deltas(d, ch):
    ts = sorted(d[ch]); out=[]
    for a,b in zip(ts, ts[1:]):
        lv = sorted(d[ch][a])
        dd = {l: d[ch][b][l]-d[ch][a][l] for l in lv}
        out.append((a,b,dd))
    return out
