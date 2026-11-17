"""LoED bed for mutants of audit_common.py. Imports audit_common from the folder given (a mutated copy), runs it on the collected
LoED files (reuse_frames_v3 plus the pass-1 receptions without FRMPayload) and prints the decision numbers, then fixed synthetic cases of
the frame rule and the reset rule with their expected answers. Counts only.
Usage (from the repository root): python -I <this folder>/loed_bed.py <folder holding audit_common.py>"""
import os, sys
sys.path.insert(0, os.path.abspath(sys.argv[1]))
import numpy as np, pandas as pd
import audit_common as C
print("audit_common from", os.path.relpath(C.__file__))

# counter test on frames (all receptions of every flaggable triple)
parts = [pd.read_parquet(p, columns=["addr", "fcnt", "size", "t", "phy", "gw"]) for p in C.loed_day_files()]
D = pd.concat(parts, ignore_index=True); del parts
u = np.load(C.LOED_UPLINKS); m0 = u["body"] == 0
D = pd.concat([D, pd.DataFrame({k: u[k][m0] for k in ("addr", "fcnt", "size", "t", "phy", "gw")}).astype({"fcnt": "int64", "size": "int64", "gw": "int8"})], ignore_index=True)
F = C.uplink_frames({k: D[k].to_numpy() for k in ("addr", "fcnt", "size", "t", "phy", "gw")})
fa, *_ = C.counter_test(F["addr"], F["fcnt"], F["size"], F["t"])
print(f"frames {len(F['addr'])}; copies merged across gateways {int(F['xgw'].sum())}; counter-flagged addresses {len(np.unique(fa))}")
del D, F, fa

# ciphertext analysis
parts = []; hit = tot = 0
for b in range(8):
    d = C.load_bucket(b); parts.append(C.analyse(d))
    h, n = C.placebo(d, np.random.default_rng(1)); hit += h; tot += n
    del d
G = C.label_groups(pd.concat(parts, ignore_index=True))
conf = set(int(x) for x in G[G.reuse].addr); ex = set(int(x) for x in G[G.examined].addr)
unres = set(int(x) for x in G[G.unresolved].addr) - ex
print(f"flagged triples with FRMPayload {len(G)}; examined {int(G.examined.sum())}; confirmed triples {int(G.reuse.sum())}; confirmed addresses {len(conf)}; "
      f"frames in confirmed triples {int(G[G.reuse].frames.sum())}; unresolved addresses {len(unres)}; identical-short pairs {int(G.ident_short.sum())}")
print(f"placebo within address buckets: {hit} related of {tot} pairs")

# Gate B reset counts on the confirmed addresses (frames from pass 1, as e18)
m = np.isin(u["addr"], list(conf)); U = {k: u[k][m] for k in ("addr", "fcnt", "size", "t", "phy", "gw")}; del u
Fr = C.uplink_frames(U); a, f, t = Fr["addr"], Fr["fcnt"], Fr["t"]; o = np.lexsort((t, a)); a, f = a[o], f[o]
st = np.r_[0, np.flatnonzero(np.diff(a)) + 1]; en = np.r_[st[1:], len(a)]
res = [C.counter_resets(f[i:j]) for i, j in zip(st, en) if j - i >= 20]
print(f"Gate B: addresses with >= 20 frames {len(res)}; with a reset {sum(r[0] > 0 for r in res)}; resets {sum(r[0] for r in res)}; drops {sum(r[1] for r in res)}; wraps {sum(r[2] for r in res)}")

# synthetic cases with known answers
def nframes(rows):
    d = pd.DataFrame(rows, columns=["t", "phy", "gw"])
    return len(C.frame_index([np.zeros(len(d), np.int64), d.phy.to_numpy()], d.t.to_numpy(), d.gw.to_numpy())[0])
h = 3600
frame_cases = [("disjoint gateway 3 h later: one frame", [(0, 1, 0), (3 * h, 1, 1)], 1),
               ("same gateway 3 h later: two frames", [(0, 1, 0), (3 * h, 1, 0)], 2),
               ("disjoint gateway 7 h later: two frames", [(0, 1, 0), (7 * h, 1, 1)], 2),
               ("third copy on a gateway that already heard it: two frames", [(0, 1, 0), (3 * h, 1, 1), (4 * h, 1, 1)], 2),
               ("different PHY payload on a disjoint gateway: two frames", [(0, 1, 0), (3 * h, 2, 1)], 2),
               ("three gateways in turn within 6 h of the first: one frame", [(0, 1, 0), (2 * h, 1, 1), (4 * h, 1, 2)], 1),
               ("second copy 5 h, third 7 h after the first (2 h after the second): two frames", [(0, 1, 0), (5 * h, 1, 1), (7 * h, 1, 2)], 2),
               ("receptions 30 s apart on one gateway: one frame", [(0, 1, 0), (30, 1, 0)], 1)]
reset_cases = [("plain run", list(range(100, 200)), 0),
               ("reset", list(range(100, 200)) + list(range(0, 50)), 1),
               ("16-bit wrap", list(range(65400, 65536)) + list(range(0, 50)), 0),
               ("two devices interleaved", [x for p in zip(range(1000, 1050), range(5000, 5050)) for x in p], 0),
               ("drop at the last frame", list(range(100, 200)) + [0], 0),
               ("small drop of 30", list(range(100, 200)) + list(range(170, 220)), 0),
               ("reset just below the wrap zone", list(range(64000, 64100)) + list(range(0, 50)), 1),
               ("reset from the wrap zone to a high value (65000 to 30000)", list(range(64900, 65001)) + list(range(30000, 30050)), 1)]
bad = 0
for lab, rows, want in frame_cases:
    got = nframes(rows); bad += got != want; print(f"synthetic frame rule, {lab}: {got}{'' if got == want else '  <-- WRONG'}")
for lab, seq, want in reset_cases:
    got = C.counter_resets(seq)[0]; bad += got != want; print(f"synthetic reset rule, {lab}: {got}{'' if got == want else '  <-- WRONG'}")
print(f"synthetic cases wrong: {bad}")
print("done")
