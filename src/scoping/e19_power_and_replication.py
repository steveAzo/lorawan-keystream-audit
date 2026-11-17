"""E19: (a) detection power of the ciphertext relatedness test by payload length and share of unchanged plaintext bytes;
(b) internal replication on LoED: the 188 day files split into the first and last 94 in date order (the first half is the 2019 block plus
the start of the 2020 block). Counts only; frames and rules come from audit_common.py.
Usage: python -I src/scoping/e19_power_and_replication.py"""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

print(f"(a) power of the test (threshold: binomial lower tail < {C.THRESH:g}); changed bytes carry uniformly random XOR; unchanged bytes XOR to zero")
print("    n bytes | k* (max differing bits to flag) | power at unchanged-byte share 0.3 / 0.5 / 0.7 / 0.9")
for n in (4, 6, 8, 12, 16, 24, 33):
    k = C.kstar(8 * n); pw = []
    for u in (.3, .5, .7, .9):
        m = round((1 - u) * n)
        pw.append(1.0 if m == 0 else C.tail_p(k, 8 * m) if k >= 0 else 0.0)
    print(f"    {n:7d} | {k:4d} | " + " / ".join(f"{x:.3f}" for x in pw))
G = pd.read_parquet("results/e15_groups.parquet"); cand = set(int(x) for x in G.addr)
files = C.loed_day_files(); h = len(files) // 2
first, second = files[:h], files[h:]
print(f"\n(b) day files {len(files)}; first half {os.path.basename(first[0])[:-8]} to {os.path.basename(first[-1])[:-8]} ({len(first)} files), "
      f"second half {os.path.basename(second[0])[:-8]} to {os.path.basename(second[-1])[:-8]} ({len(second)} files)")
def detect(fs):
    conf = set(); rows = 0
    for b in range(8):
        d = C.load_bucket(b, files=fs, addrs=cand); rows += len(d)
        G2 = C.label_groups(C.analyse(d))
        conf |= set(int(x) for x in G2[G2.reuse].addr)
    return conf, rows
A, na = detect(first); B, nb = detect(second)
print(f"frames collected: first half {na}, second half {nb}")
print(f"addresses confirmed inside the first half: {len(A)}, second half: {len(B)}, both: {len(A & B)}, either: {len(A | B)}")
print(f"of the first-half addresses, share also confirmed in the second half: {len(A & B)/max(len(A),1):.0%}")
print("done")
