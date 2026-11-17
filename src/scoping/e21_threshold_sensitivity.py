"""E21: sensitivity of the LoED reuse counts to the detector settings: relatedness threshold, minimum gap, the identical-ciphertext gap, the
gateway-aware merge, a 60 s minimum gap for related non-identical pairs (the collection keeps triples with receptions >= 60 s apart), and
testing pairs of unequal FRMPayload length on their common prefix. Pairs come
from audit_common.pairs; the threshold grid uses audit_common.tail_p, and an assertion checks that at 1e-6 it gives the same decision as
audit_common.related on every (k, n) tested. Confirmed triples with the gateway-aware merge on and off are compared triple by triple. Counts only. Usage: python -I src/scoping/e21_threshold_sensitivity.py"""
import math, os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

files = C.loed_day_files()


def collect(xgw_win):
    AD, GI, GAP, K, NB, UN = [], [], [], [], [], []; gid = 0; TK = [0]   # TK: triple key per group id (one per group, not per pair: memory)
    for b in range(8):
        d = C.load_bucket(b, files=files, xgw_win=xgw_win)
        for (a, f, n), g in d.groupby(["addr", "fcnt", "size"], sort=False):
            if len(g) < 2: continue
            t = g.t.to_numpy(); bd = list(g.body); gid += 1; TK.append((int(a) << 24) | (int(f) << 8) | int(n))
            for i, j, gap, kind, k, nb in C.pairs(t, bd, min_gap=C.COLLECT_GAP, prefix=True):
                AD.append(a); GI.append(gid); GAP.append(gap); NB.append(nb); UN.append(len(bd[i]) != len(bd[j]))
                K.append(-1 if kind == "identical" else k)
        print("xgw", xgw_win, "bucket", b, "done", flush=True)
    P = pd.DataFrame({"addr": np.array(AD, np.int64), "gid": np.array(GI, np.int64), "gap": np.array(GAP), "k": np.array(K, np.int32),
                      "nb": np.array(NB, np.int32), "uneq": np.array(UN, bool)})
    uk = P[P.k >= 0][["k", "nb"]].drop_duplicates()
    uk["lp"] = [math.log10(max(C.tail_p(int(k), int(nb)), 1e-300)) for k, nb in zip(uk.k, uk.nb)]
    same = [(lp < -6) == C.related("0" * (int(nb) // 4), "0" * (int(nb) // 4), 1e-6, int(k)) for k, nb, lp in zip(uk.k, uk.nb, uk.lp)]
    assert all(same), "tail_p grid and audit_common.related disagree at 1e-6"
    print(f"tail_p grid agrees with audit_common.related at 1e-6 on all {len(uk)} (k, n) values tested", flush=True)
    return P.merge(uk, on=["k", "nb"], how="left"), np.array(TK, np.int64)   # TK[gid]: triple key of the group


def sel(P, thr=-6, mg=C.MIN_GAP, ig=C.IDENT_GAP, rel_mg=None, prefix=False):
    rel_mg = mg if rel_mg is None else rel_mg
    r = (P.k >= 0) & (P.lp < thr) & (P.gap >= rel_mg) & (prefix | ~P.uneq)
    return P[r | ((P.k == -1) & (P.gap >= max(ig, mg)))]


P, TKP = collect(C.XGW_WIN)
main = sel(P)
eq = P[~P.uneq & (P.gap >= C.MIN_GAP)]
print("pairs >= 600 s apart, equal length:", len(eq), " of which identical:", int((eq.k == -1).sum()), "  (main rule: gateway-aware merge on)")
print("\nlog10 threshold | min gap | identical gap | addresses | triples")
for thr in (-3, -6, -9, -12):
    for mg in (600, 3600, 6 * 3600):
        for ig in (3600, 6 * 3600, 24 * 3600):
            if mg != 600 and ig != 6 * 3600: continue
            S = sel(P, thr, mg, ig)
            print(f"   {thr:4d} | {mg:6d} s | {ig // 3600:3d} h | {S.addr.nunique():4d} | {S.gid.nunique():6d}")
ca = set(main.addr); ct_on = set(TKP[main.gid.unique()].tolist())
print("\nfurther settings (threshold 1e-6, identical gap 6 h unless stated) | addresses | triples | addresses not confirmed by the main rule")
for lab, S in (("main rule", main),
               ("related pairs from 60 s (identical pairs still >= 6 h)", sel(P, rel_mg=60)),
               ("unequal-length pairs tested on their common prefix", sel(P, prefix=True)),
               ("both of the above", sel(P, rel_mg=60, prefix=True))):
    print(f"   {lab} | {S.addr.nunique()} | {S.gid.nunique()} | {len(set(S.addr) - ca)}")
sh = P[(P.k >= 0) & (P.lp < -6) & (P.gap >= 60) & (P.gap < C.MIN_GAP) & ~P.uneq]
print(f"   related equal-length pairs 60 to 600 s apart: {len(sh)} on {sh.addr.nunique()} addresses; gap quantiles 0/50/100 (s): {sh.gap.quantile([0, .5, 1]).round(0).tolist() if len(sh) else []}")
pu = P[P.uneq & (P.gap >= C.MIN_GAP)]
print(f"   unequal-length pairs >= 600 s apart: {len(pu)} in {pu.gid.nunique()} triples; related on the prefix: {int((pu.lp < -6).sum())}")
rel = P[(P.k >= 0) & (P.lp < -6) & (P.gap >= C.MIN_GAP) & ~P.uneq]; ide = P[(P.k == -1) & (P.gap >= C.IDENT_GAP)]
print(f"\naddresses by identical-late pairs only: {len(set(ide.addr) - set(rel.addr))}; by related pairs: {rel.addr.nunique()}")
nonid = int(((P.k >= 0) & (P.gap >= C.MIN_GAP) & ~P.uneq).sum())
print(f"expected chance related pairs at 1e-6 among {nonid} non-identical pairs: at most {nonid * 1e-6:.2f}")
del P
del TKP
Q, TKQ = collect(0)
print("\ngateway-aware merge off (threshold 1e-6, min gap 600 s) | addresses | triples")
for ig in (3600, 6 * 3600, 24 * 3600):
    S = sel(Q, ig=ig); print(f"   identical gap {ig // 3600:3d} h | {S.addr.nunique()} | {S.gid.nunique()}")
S0 = sel(Q); print(f"   main rule with the merge off against on: addresses {S0.addr.nunique()} against {len(ca)}; in one but not the other {len(set(S0.addr) ^ ca)}")
ct_off = set(TKQ[S0.gid.unique()].tolist())
print(f"   triple by triple: confirmed triples with the merge on {len(ct_on)}, off {len(ct_off)}; "
      f"confirmed only with the merge off (removed by the rule) {len(ct_off - ct_on)}; only with it on {len(ct_on - ct_off)}")
print("done")
