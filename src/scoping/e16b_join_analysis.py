"""E16b: DevNonce behaviour and join storms from the E16 table (LoED). Counts only.
The repeat count (n - distinct nonces) is compared with its own expectation under uniform 16-bit nonces (simulated, with the observed
per-DevEUI counts); counter-like DevNonce is tested with a strict and a loss-tolerant rule.
Usage: python -I src/scoping/e16b_join_analysis.py"""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

d = pd.read_parquet("data/derived/join_requests.parquet").sort_values(["deveui", "t"])
print("join requests", len(d), "DevEUIs", d.deveui.nunique(), "JoinEUIs", d.joineui.nunique())
n = d.groupby("deveui").size()
print("joins per DevEUI, quantiles 50/90/99, max:", n.quantile([.5, .9, .99]).round(1).tolist(), int(n.max()))
R = C.join_stats(d, "LoED DevNonce")
# how close in time are the repeats? (late duplicate receptions would sit close to the first use)
gaps = []
for e, g in d[d.deveui.isin(R.deveui)].groupby("deveui"):
    last = {}
    for x, t in zip(g.devnonce, g.t):
        if x in last: gaps.append(t - last[x])
        last[x] = t
gaps = np.array(gaps)
print(f"   repeats within 60 s of the previous use of that nonce: {int((gaps < 60).sum())}, within 10 min: {int((gaps < 600).sum())}, within 1 h: {int((gaps < 3600).sum())}, of {len(gaps)}")
d["day"] = (d.t // 86400).astype(int)
pdv = d.groupby(["deveui", "day"]).size()
print("DevEUI-days with >= 20 joins:", int((pdv >= 20).sum()), " DevEUIs:", pdv[pdv >= 20].reset_index().deveui.nunique(), " max per day", int(pdv.max()))
top = n.sort_values(ascending=False)
print("share of all join requests from the top 5 / 20 DevEUIs: %.1f%% / %.1f%%" % (100 * top.head(5).sum() / n.sum(), 100 * top.head(20).sum() / n.sum()))
print("DevEUIs that join once only:", int((n == 1).sum()), " twice or more:", int((n >= 2).sum()))
print("done")
