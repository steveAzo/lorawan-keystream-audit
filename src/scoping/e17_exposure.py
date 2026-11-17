"""E17: exposure of the keystream-reuse finding (LoED). For related (non-identical) pairs, the share of FRMPayload bytes whose XOR is zero is the share of
plaintext bytes unchanged between the two frames. The test itself requires many unchanged bytes, so the lower end of this distribution is set by the test,
not by the devices. Also: distinct ciphertexts under one keystream, and year of first observed reuse. Counts and fractions only.
Frames and pairs come from audit_common.py. Usage: python -I src/scoping/e17_exposure.py"""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

G = pd.read_parquet("results/e15_groups.parquet"); conf = set(int(x) for x in G[G.reuse].addr)
per, first, copies = {}, {}, {}
files = C.loed_day_files()
for b in range(8):
    d = C.load_bucket(b, files=files, addrs=conf)
    for (a, f, n), g in d.groupby(["addr", "fcnt", "size"], sort=False):
        if len(g) < 2: continue
        t = g.t.to_numpy(); bd = list(g.body); zs = []
        for i, j, gap, kind, k, nb in C.pairs(t, bd):
            if kind == "diff" and k <= C.kstar(nb):
                x = (int(bd[i], 16) ^ int(bd[j], 16)).to_bytes(len(bd[i]) // 2, "big"); zs.append(x.count(0) / len(x))
        if zs:
            per.setdefault(a, []).extend(zs); first[a] = min(first.get(a, 9e18), t.min()); copies.setdefault(a, []).append(len(set(g.body)))
    print("bucket", b, "done", flush=True)
A = pd.DataFrame({"addr": list(per), "unchanged": [np.median(v) for v in per.values()], "first_t": [first[a] for a in per], "max_copies": [max(copies[a]) for a in per]})
print("addresses with related non-identical pairs:", len(A))
print("per-address median share of unchanged plaintext bytes, quantiles 10/25/50/75/90:", A.unchanged.quantile([.1, .25, .5, .75, .9]).round(2).tolist())
print("addresses whose median pair has >= 50% unchanged bytes:", int((A.unchanged >= .5).sum()), " >= 80%:", int((A.unchanged >= .8).sum()))
print("distinct ciphertexts under one keystream (max per address, all frames of a triple) quantiles 50/90, max:", A.max_copies.quantile([.5, .9]).tolist(), int(A.max_copies.max()))
print("addresses by year of first observed reuse:", pd.to_datetime(A.first_t, unit="s").dt.year.value_counts().sort_index().to_dict())
print("done")
