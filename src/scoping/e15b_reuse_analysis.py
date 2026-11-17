"""E15b: classify the (DevAddr, FCnt, size) triples flagged by the counter test by ciphertext relation, with the rules of audit_common.py,
from the LoED receptions collected by src/data/collect_loed.py: receptions merged into frames (same PHY payload digest, gateway-aware merge),
any two frames of a triple at least MIN_GAP apart, equal-length guard, all pairs up to 80 frames per triple, identical pairs under 6 h counted
as unresolved. Writes results/e15_groups.parquet (kept local: it holds addresses). Counts only; no payload is decoded or printed. Usage: python -I src/scoping/e15b_reuse_analysis.py"""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

files = C.loed_day_files(); print("day files:", len(files))
parts = []; xg = xa = 0
for b in range(8):
    d = C.load_bucket(b, files=files); xg += int(d.xgw.sum()); xa += int((d.xgw > 0).sum())
    parts.append(C.analyse(d)); print("bucket", b, "done", flush=True)
G = C.label_groups(pd.concat(parts, ignore_index=True))
G.to_parquet("results/e15_groups.parquet", index=False)
E, R = G[G.examined], G[G.reuse]
ex, conf = set(E.addr), set(R.addr)
print(f"gateway-aware merge: {xg} copies on disjoint gateways within {C.XGW_WIN // 3600} h merged into {xa} frames (collected receptions only)")
print(f"flagged triples with FRMPayload: {len(G)} on {G.addr.nunique()} addresses; examined (a testable pair): {len(E)} on {len(ex)} addresses; capped at {C.MAX_FRAMES} frames: {int(G.capped.sum())}")
print(f"unresolved triples (only identical pairs under {C.IDENT_GAP//3600} h): {int(G.unresolved.sum())}; addresses with unresolved triples and no examined triple: {len(set(G[G.unresolved].addr) - ex)}")
print(f"triples with related or identical pairs: {len(R)} ({len(R)/len(E):.1%} of examined); with only unrelated pairs: {int((E.examined & ~E.reuse).sum())}; with unequal-length pairs: {int((G.unequal > 0).sum())}")
D = E.groupby("addr").agg(reuse=("reuse", "sum"), unrel=("unrelated", lambda s: (s > 0).sum()))
print(f"confirmed addresses: {len(conf)}  with >= 3 confirmed triples: {int((D.reuse >= 3).sum())}  with >= 20: {int((D.reuse >= 20).sum())}")
print(f"share of confirmed addresses that also show unrelated pairs (several keys behind one address): {(D.loc[list(conf)].unrel > 0).mean():.1%}")
print(f"frames in confirmed triples: {int(R.frames.sum())} (receptions {int(R.rows.sum())}); by PHY size (top): {R.groupby('size').frames.sum().sort_values(ascending=False).head(6).to_dict()}")
print(f"confirmed triples with identical-late pairs {int((R.identical > 0).sum())}, with related pairs {int((R.related > 0).sum())}; addresses confirmed only by identical-late pairs: {len(conf - set(R[R.related > 0].addr))}")
sp = R.groupby("addr").identical.sum(); rp = R.groupby("addr").related.sum()
print(f"supporting pairs per confirmed address: exactly 1: {int(((sp + rp) == 1).sum())}, 2: {int(((sp + rp) == 2).sum())}, >= 10: {int(((sp + rp) >= 10).sum())}")
print("confirmed-triple span (days) quantiles 25/50/75/95:", R.span_days.quantile([.25, .5, .75, .95]).round(2).tolist())
print("done")
