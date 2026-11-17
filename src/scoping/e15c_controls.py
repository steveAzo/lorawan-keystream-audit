"""E15c: concentration and controls for E15b (LoED), with the rules of audit_common.py. Counts only.
Placebo: frames with the same FCnt and size from DIFFERENT addresses (different keystream by construction) must almost never test as related.
Same-address control: frames of one confirmed address with DIFFERENT counters and the same size (same key, different keystream)
must test as unrelated; this rules out unencrypted payloads, a keystream that ignores the counter, and byte artefacts of the capture.
For zero hits in N pairs the 95% upper bound on the per-pair rate is 1 - 0.05^(1/N). The placebo is
audit_common.placebo (shared with E23); the same-address control has its own sampling but uses audit_common.related. Usage: python -I src/scoping/e15c_controls.py"""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

G = pd.read_parquet("results/e15_groups.parquet"); R = G[G.reuse]
by = R.groupby("addr").frames.sum().sort_values(ascending=False)
print("confirmed addresses:", len(by), " frames in confirmed triples:", int(by.sum()))
print("top 1 / 5 / 10 / 20 addresses hold %.1f%% / %.1f%% / %.1f%% / %.1f%% of those frames" % tuple(100 * by.head(k).sum() / by.sum() for k in (1, 5, 10, 20)))
bg = R.groupby("addr").size()
print("confirmed triples per address, quantiles 25/50/75/90:", bg.quantile([.25, .5, .75, .9]).round(1).tolist(), " max", int(bg.max()))
print("addresses with confirmed triples spanning > 7 days:", R[R.span_days > 7].addr.nunique())
rest = R[~R.addr.isin(by.head(20).index)]
print("excluding top 20: addresses", rest.addr.nunique(), " triples", len(rest), " frames", int(rest.frames.sum()))
conf = set(int(x) for x in R.addr); rng = np.random.default_rng(1)
s_hit = s_tot = a_hit = a_tot = 0; s_addr = set()
files = C.loed_day_files()
for b in range(8):
    d = C.load_bucket(b, files=files)
    one = d.drop_duplicates(["addr", "fcnt", "size"])
    # same address, different counter
    for ad, g in one[one.addr.isin(conf)].groupby("addr"):
        idx = rng.permutation(len(g))[:1500]; f = g.fcnt.to_numpy()[idx]; n = g["size"].to_numpy()[idx]; bb = g.body.to_numpy()[idx]
        for i in range(len(idx) - 2):
            for j in (i + 1, i + 2):
                if f[i] == f[j] or n[i] != n[j] or len(bb[i]) != len(bb[j]) or bb[i] == bb[j]: continue
                s_tot += 1; s_hit += C.related(bb[i], bb[j]); s_addr.add(ad)
        byf = {(x, y): z for x, y, z in zip(g.fcnt, g["size"], g.body)}
        for (x, y), z in list(byf.items())[:3000]:
            o = byf.get((x + 1, y))
            if o is not None and len(o) == len(z) and o != z: a_tot += 1; a_hit += C.related(z, o)
    print("bucket", b, "done", flush=True)
ub = C.upper95
print(f"same-address control (different FCnt, same size): {s_hit} related of {s_tot} pairs over {len(s_addr)} addresses; 95% upper bound {ub(s_tot):.1e}")
print(f"adjacent-counter control (FCnt and FCnt+1, same size): {a_hit} related of {a_tot} pairs")
# placebo: different addresses, same FCnt and size (one frame per triple), over all addresses at once (not by address bucket),
# (i) among the confirmed addresses (the worst case), (ii) among all addresses with collected frames
cols = ["addr", "fcnt", "size", "body"]
allf = pd.concat([pd.read_parquet(p, columns=cols).drop_duplicates(["addr", "fcnt", "size"]) for p in files], ignore_index=True).drop_duplicates(["addr", "fcnt", "size"])
for label, one in (("confirmed addresses", allf[allf.addr.isin(conf)]), ("all addresses", allf)):
    hit, tot = C.placebo(one, rng)
    print(f"placebo among {label} (different addresses, same FCnt and size): {hit} related of {tot} pairs; 95% upper bound on the per-pair rate {ub(tot):.1e}")
print("done")
