"""Data for the manuscript figures that the result files do not already hold. Counts, z-scores, ranks and counters only: no payload is
decoded, and no address is written (addresses are replaced by ranks or by the label "address A").
Outputs (results/):
  fig_zscores.csv        histogram (bin width 0.25) of z = (k - 4n) / sqrt(2n) for the LoED pairs the ciphertext test examines
                         (same DevAddr, FCnt and size, >= MIN_GAP apart, equal length, not identical; audit_common.pairs) and for
                         placebo pairs (different addresses; the sampling of audit_common.placebo, reproduced and checked pair for pair)
  fig_concentration.csv  frames in confirmed triples per confirmed address, sorted, by capture (LoED, Brno, Vienna; uplink concentrator)
  fig_counter_trace.csv  frames (time, FCnt, in a confirmed triple) of one confirmed LoED address chosen by a stated rule
  fig_data.txt           log, with the selection rule and the checks
Usage (from the repository root): python -I src/figures/fig_data.py   (steps run one after another and free their memory)"""
import math, os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scoping"))
import audit_common as C

LOG = open("results/fig_data.txt", "w", encoding="utf-8")
def log(*a):
    s = " ".join(str(x) for x in a); print(s, flush=True); LOG.write(s + "\n")

EDGES = np.arange(-60, 15.25, 0.25)
def z(k, nb):
    return (k - nb / 2) / math.sqrt(nb / 4)

# ---------------------------------------------------------------- (a) z-scores: examined same-counter pairs and placebo pairs (LoED)
h_same = np.zeros(len(EDGES) - 1, np.int64); h_plac = np.zeros(len(EDGES) - 1, np.int64)
n_same = n_ident = n_rel = n_plac = n_plac_ref = 0; zmin_plac = 99.0
files = C.loed_day_files()
for b in range(8):
    d = C.load_bucket(b, files=files)
    tg = d.groupby(["addr", "fcnt", "size"], sort=False).t
    dd = d[(tg.transform("max") - tg.transform("min")) >= C.MIN_GAP]
    zs = []
    for _, g in dd.groupby(["addr", "fcnt", "size"], sort=False):
        if len(g) < 2: continue
        for i, j, gap, kind, k, nb in C.pairs(g.t.to_numpy(), list(g.body)):
            if kind == "identical": n_ident += 1
            elif kind == "diff":
                zs.append(z(k, nb)); n_rel += C.related("0" * (nb // 4), "0" * (nb // 4), C.THRESH, k)
    n_same += len(zs); h_same += np.histogram(np.clip(zs, EDGES[0], EDGES[-1] - 1e-9), EDGES)[0]
    # placebo: the sampling of audit_common.placebo (same rng seed and order), collecting z instead of the count
    rng = np.random.default_rng(1); zp = []
    one = d.drop_duplicates(["addr", "fcnt", "size"])
    for (f, n), g in one.groupby(["fcnt", "size"]):
        if g.addr.nunique() < 2: continue
        idx = rng.permutation(len(g))[:60]; a = g.addr.to_numpy()[idx]; bb = g.body.to_numpy()[idx]
        for i in range(len(idx) - 1):
            for j in range(i + 1, min(i + 4, len(idx))):
                if a[i] == a[j] or len(bb[i]) != len(bb[j]) or bb[i] == bb[j]: continue
                zp.append(z(C.diff_bits(bb[i], bb[j]), 4 * len(bb[i])))
    hit, tot = C.placebo(d, np.random.default_rng(1))
    assert tot == len(zp), (tot, len(zp))
    n_plac += len(zp); n_plac_ref += tot; zmin_plac = min(zmin_plac, min(zp) if zp else 99)
    h_plac += np.histogram(np.clip(zp, EDGES[0], EDGES[-1] - 1e-9), EDGES)[0]
    del d, dd, one
    log("z-scores: bucket", b, "done")
pd.DataFrame({"z_left": EDGES[:-1], "same_counter": h_same, "placebo": h_plac}).to_csv("results/fig_zscores.csv", index=False)
log(f"(a) examined non-identical same-counter pairs {n_same} (related at {C.THRESH:g}: {n_rel}); identical pairs {n_ident}; "
    f"placebo pairs {n_plac} (audit_common.placebo on the same buckets and seed: {n_plac_ref}, equal: {n_plac == n_plac_ref}); lowest placebo z {zmin_plac:.2f}")
for n in (4, 12, 33, 64):
    log(f"    z of the threshold k* for n = {n} bytes: {z(C.kstar(8 * n), 8 * n):.2f}")

# ---------------------------------------------------------------- (b) concentration of confirmed frames by address rank
G = pd.read_parquet("results/e15_groups.parquet"); R = G[G.reuse]
rows = [("LoED", r, int(v)) for r, v in enumerate(R.groupby("addr").frames.sum().sort_values(ascending=False), 1)]
for city in ("brno", "wien"):
    RU = pd.read_parquet(f"data/derived/povalac/{city}_reuse.parquet"); RU = RU[RU.conc.to_numpy() == 1].drop(columns="conc")
    Gc = C.label_groups(C.analyse(C.merge_receptions(RU))); Rc = Gc[Gc.reuse]
    rows += [({"brno": "Brno", "wien": "Vienna"}[city], r, int(v)) for r, v in enumerate(Rc.groupby("addr").frames.sum().sort_values(ascending=False), 1)]
    del RU, Gc
Cn = pd.DataFrame(rows, columns=["capture", "rank", "frames"]); Cn.to_csv("results/fig_concentration.csv", index=False)
for cap, g in Cn.groupby("capture", sort=False):
    s = g.frames.to_numpy(); log(f"(b) {cap}: confirmed addresses {len(s)}, frames {s.sum()}, top 1/5 share {s[:1].sum()/s.sum():.1%} / {s[:5].sum()/s.sum():.1%}")

# ---------------------------------------------------------------- (c) counter trace of one confirmed LoED address
D = pd.read_csv("data/derived/e18_devices_addr.csv")   # written by e18, kept local
rule = "confirmed LoED address with 3 to 8 counted resets and 300 to 3,000 frames; of these, the one with the most frames"
cand = D[(D.resets >= 3) & (D.resets <= 8) & (D.frames >= 300) & (D.frames <= 3000)].sort_values("frames", ascending=False)
addr = int(cand.addr.iloc[0])
u = np.load(C.LOED_UPLINKS)
F = C.uplink_frames(u, mask=u["addr"] == addr); del u
o = np.argsort(F["t"], kind="mergesort")
ct = set(zip(R[R.addr == addr].fcnt.astype(int), R[R.addr == addr]["size"].astype(int)))
conf = np.array([(int(f), int(s)) in ct for f, s in zip(F["fcnt"][o], F["size"][o])])
T = pd.DataFrame({"t": F["t"][o], "fcnt": F["fcnt"][o], "confirmed": conf})
T.to_csv("results/fig_counter_trace.csv", index=False)
res = C.counter_resets(T.fcnt.to_numpy())
log(f"(c) rule: {rule}; candidates {len(cand)}; chosen: frames {len(T)}, counted resets {res[0]} (e18: {int(cand.resets.iloc[0])}), "
    f"frames in confirmed triples {int(conf.sum())}, span {(T.t.max() - T.t.min()) / 86400:.1f} days; the address itself is not written")
log("done")
