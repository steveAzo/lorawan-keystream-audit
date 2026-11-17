"""E14: capture description and counter-test census for LoED, from the pass-1 table of src/data/collect_loed.py (addresses and counters read from the
payload bytes, one row per reception). The counter test (any two frames of a triple at least MIN_GAP apart) runs on frames (audit_common frame
rule, with the gateway-aware merge), and is also reported on receptions and on frames without the gateway-aware merge. Counts only.
Usage: python -I src/scoping/e14_counter_reuse_census.py"""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

u = np.load(C.LOED_UPLINKS)
a, f, s, t, body, day, names = u["addr"], u["fcnt"].astype(np.int64), u["size"].astype(np.int64), u["t"], u["body"], u["day"], list(u["names"])
blocks = C.capture_blocks(names)
print(f"day files {len(names)}, with data uplinks {len(np.unique(day))}; gateways {len(u['gateways'])}; capture blocks: " +
      "; ".join(f"{np.datetime64(int(x), 's').astype('datetime64[D]')} to {np.datetime64(int(y) - 86400, 's').astype('datetime64[D]')} ({n} days)" for x, y, n in blocks) +
      f"; first-to-last span {(blocks[-1][1] - blocks[0][0]) / 86400:.0f} days")
ua = np.unique(a); ub = np.unique(a[body == 1])
cnt = np.bincount(np.searchsorted(ua, a))
print(f"addresses with data uplinks {len(ua)}; with at least one FRMPayload byte {len(ub)}; with >= 50 receptions {int((cnt >= 50).sum())}")
fa, *_ = C.counter_test(a, f, s, t)
ct = [("receptions (not merged into frames)", len(fa), len(np.unique(fa)))]
m = body == 1; n_rec = len(a); del a, f, s, t, fa, day, cnt
for lab, xw in (("frames without the gateway-aware merge", 0), ("frames with the gateway-aware merge (main)", C.XGW_WIN)):
    F = C.uplink_frames(u, xgw_win=xw)
    print(f"{lab}: {len(F['addr'])}" + (f" ({int((F['xgw'] > 0).sum())} frames absorbed {int(F['xgw'].sum())} copies on disjoint gateways within {C.XGW_WIN // 3600} h)" if xw else ""))
    fa, *_ = C.counter_test(F["addr"], F["fcnt"], F["size"], F["t"]); ct.append((lab, len(fa), len(np.unique(fa)))); del F, fa
print(f"data-uplink receptions {n_rec}; counter test (any two rows of a (DevAddr, FCnt, size) triple >= {C.MIN_GAP} s apart):")
for lab, nt, na in ct: print(f"   on {lab}: triples {nt}, addresses {na}")
F1b = C.uplink_frames(u, mask=m)
fa2, *_ = C.counter_test(F1b["addr"], F1b["fcnt"], F1b["size"], F1b["t"])
print(f"   the same on frames with FRMPayload only (main rule): triples {len(fa2)}, addresses {len(np.unique(fa2))}")
print("done")
