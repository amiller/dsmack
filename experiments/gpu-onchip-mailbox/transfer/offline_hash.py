#!/usr/bin/env python3
# Recompute the value channel's final GPU hash from the public seed, off the Mac.
# Same recurrence as transfer2_host.mm: words are the high 32 bits of a 64-bit LCG.
# usage: offline_hash.py <transfer2_host output .json>...
import json, sys
M, F = (1 << 64) - 1, (1 << 32) - 1
def final_hash(seed, trips):
    x, h = ((seed << 32) | 0x9E3779B97F4A7C15) & M, 0
    for _ in range(trips):
        w = []
        for _ in range(7):
            x = (x * 6364136223846793005 + 1442695040888963407) & M
            w.append(x >> 32)
        c = 0xA5A5A5A5
        for v in w: c ^= v
        for v in w + [c]: h = ((h ^ v) * 16777619) & F
    return h
for p in sys.argv[1:]:
    c = json.load(open(p))['chunks_arr'][0]
    h = final_hash(c['seed'], c['trips_done'])
    print(p, 'seed', c['seed'], 'trips', c['trips_done'], 'offline', h, 'gpu', c['gpu_final_hash'], 'match', h == c['gpu_final_hash'])
