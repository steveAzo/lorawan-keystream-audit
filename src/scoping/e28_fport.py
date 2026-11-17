"""E28: FPort of the LoED triples (port 0 is encrypted with NwkSKey, other ports with AppSKey; a triple is keyed by DevAddr, FCnt and PHY size,
so frames on different ports can share a triple). Ports come from collect_loed_fport.py (one per PHY payload digest) and join to the
receptions of reuse_frames_v3; triples and their outcome come from E27 (results/e27_triples.parquet). Counts only.
Usage: python -I src/scoping/e28_fport.py"""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

P = pd.read_parquet("data/derived/loed_fport_v3.parquet").set_index("phy").fport
T = pd.read_parquet("results/e27_triples.parquet")
parts = []
for p in C.loed_day_files():
    x = pd.read_parquet(p, columns=["addr", "fcnt", "size", "phy"])
    x["fport"] = P.reindex(x.phy.to_numpy()).to_numpy()
    parts.append(x.drop(columns="phy").drop_duplicates())
X = pd.concat(parts, ignore_index=True).drop_duplicates()
print(f"receptions without a port (digest not found): {int(X.fport.isna().sum())}")
S = X.groupby(["addr", "fcnt", "size"]).fport.agg(nports="nunique", port0=lambda s: bool((s == 0).any())).reset_index()
T = T.merge(S, on=["addr", "fcnt", "size"], how="left")
print(f"flagged triples {len(T)}; with port information {int(T.nports.notna().sum())}")
for lab, w in (("one port, port 0", (T.nports == 1) & T.port0), ("one port above 0", (T.nports == 1) & ~T.port0.astype(bool)), ("several ports", T.nports > 1)):
    x = T[w]; e = x[x.examined]
    print(f"   {lab}: triples {len(x)} on {x.addr.nunique()} addresses; examined {len(e)}; confirmed {int(x.confirmed.sum())} "
          f"({x.confirmed.sum() / max(len(e), 1):.1%} of examined) on {x[x.confirmed].addr.nunique()} addresses")
c = T[T.confirmed]
print(f"confirmed addresses whose confirmed triples are all on ports above 0: {c.groupby('addr').port0.any().eq(False).sum()} of {c.addr.nunique()}")
print("done")
