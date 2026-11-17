"""E27: checks requested by the pre-submission review (LoED), all with the rules of audit_common.py. Counts only; no payload is decoded or printed.
1. Multiple comparisons. The threshold tau = 1e-6 bounds the chance that ONE pair of independent ciphertexts is called related. A triple or an
   address is confirmed when ANY of its pairs is related, so its family-wise bound is (number of pairs tested) x tau by the union bound, which
   holds whatever the dependence between pairs. Reported: pairs tested per triple and per address; the union bound summed over all examined
   triples and addresses (an upper bound on the expected number confirmed by chance); and the confirmed counts when tau is divided by the pairs
   tested per triple (Bonferroni, triple level), per address (address level), and over the whole capture (study level, family-wise 1e-6 and 0.05).
2. Evidence categories. Addresses with related non-identical pairs, addresses confirmed only by identical ciphertexts, and unresolved addresses,
   for identical gaps of 1 to 48 h, by addresses and by triples.
3. The 80-frame cap. Triples with more than 80 frames, their frames, and the pairs left out; on these triples the ciphertext test is rerun on
   all their frames and on 80 frames spread evenly over the triple.
4. The gateway-aware merge. (a) Merge window 6 h (main), 1 h and off: flagged, examined, confirmed and unresolved triples and addresses, and a
   triple-by-triple check that every triple confirmed with the merge on is confirmed with it off (merging only removes frames whose PHY payload
   is byte-identical to an earlier frame, so it cannot add a pair). (b) On all data uplinks (pass-1 table): consecutive frames with the same
   (DevAddr, FCnt, size, PHY payload), by time gap, gateway overlap and gateways per side. (c) Clock-offset consistency: for copies on
   disjoint gateways 10 min to 6 h apart, the spread of the gap within each (gateway set pair, day).
Writes results/e27_triples.parquet (kept local: it holds addresses). Usage: python -I src/scoping/e27_revision_checks.py"""
import math, os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

H = 3600
_LP = {}
def lp(k, nb):
    """log10 P(Bin(nb, .5) <= k), floored at -300."""
    key = (k, nb)
    if key not in _LP: _LP[key] = math.log10(max(C.tail_p(k, nb), 1e-300))
    return _LP[key]


def scan(t, bd):
    """Pairs of the given frames (all of them: callers pass the subset). Returns (m tested, min log10 p, max identical gap, unequal, any identical)."""
    m = 0; mn = 0.0; mi = -1.0; une = 0; anyi = False
    for i, j, gap, kind, k, nb in C.pairs(t, bd, max_frames=len(bd)):
        if kind == "unequal": une += 1; continue
        if kind == "identical": anyi = True; mi = max(mi, gap); continue
        m += 1; mn = min(mn, lp(k, nb))
    return m, mn, mi, une, anyi


def run(xgw_win, extra):
    rows = []; files = C.loed_day_files()
    for b in range(8):
        d = C.load_bucket(b, files=files, xgw_win=xgw_win)
        tg = d.groupby(["addr", "fcnt", "size"], sort=False).t
        d = d[(tg.transform("max") - tg.transform("min")) >= C.MIN_GAP]
        for (a, f, n), g in d.groupby(["addr", "fcnt", "size"], sort=False):
            t = g.t.to_numpy(); bd = list(g.body); nf = len(t)
            m, mn, mi, une, anyi = scan(t[:C.MAX_FRAMES], bd[:C.MAX_FRAMES])
            r = dict(addr=int(a), fcnt=int(f), size=int(n), frames=nf, m=m, minlp=mn, maxident=mi, unequal=une, anyident=anyi)
            if extra and nf > C.MAX_FRAMES:
                ts = np.sort(t); r["pairs_all"] = int(sum(len(ts) - np.searchsorted(ts, ts + C.MIN_GAP)))
                r["pairs_80"] = int(sum(C.MAX_FRAMES - np.searchsorted(ts[:C.MAX_FRAMES], ts[:C.MAX_FRAMES] + C.MIN_GAP)))
                r["m_all"], r["minlp_all"], r["maxident_all"], *_ = scan(t, bd)
                ix = np.unique(np.linspace(0, nf - 1, C.MAX_FRAMES).round().astype(int))
                r["m_even"], r["minlp_even"], r["maxident_even"], *_ = scan(t[ix], [bd[i] for i in ix])
            rows.append(r)
        print("xgw", xgw_win, "bucket", b, "done", flush=True)
    T = pd.DataFrame(rows)
    T["rel"] = T.minlp < -6
    T["confirmed"] = T.rel | (T.maxident >= C.IDENT_GAP)
    T["examined"] = (T.m > 0) | (T.maxident >= C.IDENT_GAP)
    T["unresolved"] = (T.m == 0) & T.anyident & (T.maxident < C.IDENT_GAP)
    return T


def q(s, p=(.5, .9, .99, 1)):
    return [round(float(x), 1) for x in s.quantile(list(p))]


# ---------------------------------------------------------------- main run (merge 6 h), with the cap analysis
T = run(C.XGW_WIN, True)
T.to_parquet("results/e27_triples.parquet", index=False)
conf = set(T[T.confirmed].addr); E = T[T.examined]
print(f"\n[0] reproduction: flagged triples with FRMPayload {len(T)}; examined {len(E)}; confirmed triples {int(T.confirmed.sum())} on {len(conf)} addresses")
assert int(T.confirmed.sum()) == 45207 and len(conf) == 236, "does not reproduce the main result"

print("\n[1] multiple comparisons (tau = 1e-6 per pair; m = non-identical equal-length pairs tested)")
Mtot = int(T.m.sum()); print(f"   pairs tested: {Mtot}; triples with a tested pair {int((T.m > 0).sum())}")
tm = T[T.m > 0].m; print(f"   pairs per triple, quantiles 50/90/99/max: {q(tm)}; triples with m = 1: {int((tm == 1).sum())} ({(tm == 1).mean():.1%})")
A = T.groupby("addr").agg(M=("m", "sum"), minlp=("minlp", "min"), rel=("rel", "any"), conf=("confirmed", "any"),
                          identlate=("maxident", lambda s: bool((s >= C.IDENT_GAP).any())), ntrip_rel=("rel", "sum"))
Am = A[A.M > 0]; print(f"   pairs per address (addresses with a tested pair: {len(Am)}), quantiles 50/90/99/max: {q(Am.M)}")
eb_t = float(np.minimum(1, T[T.m > 0].m * 1e-6).sum()); eb_a = float(np.minimum(1, Am.M * 1e-6).sum())
print(f"   union bound on chance confirmations under the null: triples <= {eb_t:.2f}; addresses <= {eb_a:.2f} (sum over examined units of min(1, m x tau))")
relA = A[A.rel]; print(f"   addresses confirmed by related pairs (main): {len(relA)}; their family-wise bound m x tau, quantiles 50/90/max: "
                       f"{[f'{x:.1e}' for x in (relA.M * 1e-6).quantile([.5, .9, 1])]}")
lt = T.minlp + np.log10(T.m.clip(lower=1)); la = A.minlp + np.log10(A.M.clip(lower=1))
for lab, ra in (("triple-level Bonferroni (tau / m per triple)", set(T[(T.m > 0) & (lt < -6)].addr)),
                ("address-level Bonferroni (tau / M per address)", set(A[(A.M > 0) & (la < -6)].index)),
                (f"study-level Bonferroni, family-wise 1e-6 (tau = 1e-6 / {Mtot})", set(T[T.minlp < -6 - math.log10(Mtot)].addr)),
                (f"study-level Bonferroni, family-wise 0.05 (tau = 0.05 / {Mtot})", set(T[T.minlp < math.log10(.05 / Mtot)].addr))):
    nt = {"triple": int(((T.m > 0) & (lt < -6)).sum())}.get(lab.split("-")[0], None)
    print(f"   {lab}: addresses with a related pair {len(ra)} of {len(relA)}" + (f"; triples {nt}" if nt is not None else ""))
il = set(A[A.identlate & ~A.rel].index)
print(f"   addresses confirmed only by identical pairs >= 6 h (no p-value; unaffected by tau): {len(il)}")
sw = set(T[T.minlp < -6 - math.log10(Mtot)].addr)
print(f"   addresses with related pairs that fail study-level family-wise 1e-6: {len(set(relA.index) - sw)}; of these with one related triple: "
      f"{int((A.loc[list(set(relA.index) - sw)].ntrip_rel == 1).sum())}")
print(f"   related triples per address (addresses with related pairs): 1: {int((relA.ntrip_rel == 1).sum())}, 2: {int((relA.ntrip_rel == 2).sum())}, >= 3: {int((relA.ntrip_rel >= 3).sum())}")
print(f"   min log10 p of related triples, quantiles 50/10/1: {q(T[T.rel].minlp, (.5, .1, .01))}; weakest {T[T.rel].minlp.max():.2f}")

print("\n[2] evidence categories by identical gap (related pairs: tau 1e-6, gap >= 10 min)")
relT = T.rel; ra = set(T[relT].addr)
print("   identical gap | addresses: related | identical only | total | unresolved (no examined triple) || triples: related | identical only | unresolved")
for g in (1, 2, 3, 6, 12, 24, 48):
    io = T[~relT & (T.maxident >= g * H)]; ia = set(io.addr) - ra
    ex = (T.m > 0) | (T.maxident >= g * H); un = T[(T.m == 0) & T.anyident & (T.maxident < g * H)]
    ua = set(un.addr) - set(T[ex].addr)
    print(f"   {g:3d} h | {len(ra)} | {len(ia)} | {len(ra | ia)} | {len(ua)} || {int(relT.sum())} | {len(io)} | {len(un)}")
io6 = T[~relT & (T.maxident >= C.IDENT_GAP) & T.addr.isin(il)]
print(f"   the {len(il)} identical-only addresses: triples {len(io6)}; their longest identical gap per address (h): "
      f"{sorted(round(x / H, 1) for x in io6.groupby('addr').maxident.max())}")

print("\n[3] the 80-frame cap")
cp = T[T.frames > C.MAX_FRAMES]; fl = int(T.frames.sum())
print(f"   triples with more than {C.MAX_FRAMES} frames: {len(cp)} of {len(T)} ({len(cp) / len(T):.2%}), on {cp.addr.nunique()} addresses; their frames {int(cp.frames.sum())} "
      f"of {fl} ({cp.frames.sum() / fl:.1%}); frames beyond the cap {int((cp.frames - C.MAX_FRAMES).sum())}")
print(f"   pairs >= 10 min apart on these triples: all frames {int(cp.pairs_all.sum())}, first 80 {int(cp.pairs_80.sum())}, left out {int((cp.pairs_all - cp.pairs_80).sum())}")
for lab, mc, ic in (("first 80 (main)", "minlp", "maxident"), ("80 spread evenly", "minlp_even", "maxident_even"), ("all frames", "minlp_all", "maxident_all")):
    c = (cp[mc] < -6) | (cp[ic] >= C.IDENT_GAP)
    print(f"   {lab}: capped triples confirmed {int(c.sum())} on {cp[c].addr.nunique()} addresses")
call = (cp.minlp_all < -6) | (cp.maxident_all >= C.IDENT_GAP)
newA = set(cp[call].addr) - conf
print(f"   addresses confirmed only when all frames of the capped triples are tested: {len(newA)}; triples confirmed with all frames but not on the first 80: "
      f"{int((call & ~cp.confirmed).sum())}; on the first 80 but not with all frames: {int((cp.confirmed & ~call).sum())}")
ce = (cp.minlp_even < -6) | (cp.maxident_even >= C.IDENT_GAP)
print(f"   addresses confirmed only with the evenly spread sample: {len(set(cp[ce].addr) - conf)}")
main_keys = set(zip(T[T.confirmed].addr, T[T.confirmed].fcnt, T[T.confirmed]["size"]))
summary_main = (len(T), len(E), int(T.confirmed.sum()), len(conf), int(T.unresolved.sum()))
del T, E, A, cp

# ---------------------------------------------------------------- merge window 1 h and off
print("\n[4a] gateway-aware merge window | flagged triples (FRMPayload) | examined | confirmed triples | confirmed addresses | unresolved triples | unresolved addresses")
print(f"   6 h (main) | {summary_main[0]} | {summary_main[1]} | {summary_main[2]} | {summary_main[3]} | {summary_main[4]} | 36")
for lab, w in (("1 h", H), ("off", 0)):
    X = run(w, False); cx = set(X[X.confirmed].addr)
    ux = set(X[X.unresolved].addr) - set(X[X.examined].addr)
    kx = set(zip(X[X.confirmed].addr, X[X.confirmed].fcnt, X[X.confirmed]["size"]))
    print(f"   {lab} | {len(X)} | {int(X.examined.sum())} | {int(X.confirmed.sum())} | {len(cx)} | {int(X.unresolved.sum())} | {len(ux)}"
          f"   (confirmed triples with the 6-h merge and not here: {len(main_keys - kx)}; here and not with the 6-h merge: {len(kx - main_keys)})")
    del X

print("\n[4b] consecutive frames with the same (DevAddr, FCnt, size, PHY payload), all data uplinks, merge off")
u = np.load(C.LOED_UPLINKS)
a, f, s, t, ph, gw = u["addr"], u["fcnt"].astype(np.int64), u["size"].astype(np.int64), u["t"], u["phy"], u["gw"]
first, rows, gm, xgw = C.frame_index([C.triple_key(a, f, s), ph], t, gw, xgw_win=0)
k1 = C.triple_key(a[first], f[first], s[first]); p1 = ph[first]; t1 = t[first]; day = (t1 // 86400).astype(np.int64)
del a, f, s, ph, gw, u
same = np.r_[False, (k1[1:] == k1[:-1]) & (p1[1:] == p1[:-1])]
i = np.flatnonzero(same); gap = t1[i] - t1[i - 1]; ga, gb = gm[i - 1], gm[i]
def pc(x): return sum(((x >> b) & 1) for b in range(63))
na, nb = pc(ga), pc(gb); disj = (ga & gb) == 0
bins = [(60, 600, "1-10 min"), (600, H, "10 min-1 h"), (H, 6 * H, "1-6 h"), (6 * H, 1e12, ">= 6 h")]
print(f"   consecutive same-payload frame pairs: {len(i)}")
print("   gap | overlapping gateways | disjoint: 1 vs 1 | 1 vs >=2 | >=2 vs >=2")
for lo, hi, lab in bins:
    w = (gap >= lo) & (gap < hi)
    print(f"   {lab} | {int((w & ~disj).sum())} | {int((w & disj & (na == 1) & (nb == 1)).sum())} | {int((w & disj & ((na == 1) ^ (nb == 1))).sum())} | "
          f"{int((w & disj & (na >= 2) & (nb >= 2)).sum())}")
w = disj & (gap >= 600) & (gap < 6 * H)
D = pd.DataFrame({"ga": ga[w], "gb": gb[w], "day": day[i][w], "gap": gap[w]})
D["dev"] = (D.gap - D.groupby(["ga", "gb", "day"]).gap.transform("median")).abs()
D["n"] = D.groupby(["ga", "gb", "day"]).gap.transform("size")
print(f"\n[4c] copies on disjoint gateways 10 min to 6 h apart: {len(D)}; (gateway set, gateway set) pairs {D.groupby(['ga', 'gb']).ngroups}; "
      f"gateway sets with 3+ gateways on either side {int(((pc(D.ga.to_numpy()) >= 3) | (pc(D.gb.to_numpy()) >= 3)).sum())}")
for tol in (1, 10, 60):
    print(f"   within {tol} s of the median gap of their (gateway pair, day): {(D.dev <= tol).mean():.1%}"
          f"   (groups of at least 5 copies: {(D[D.n >= 5].dev <= tol).mean():.1%} of {int((D.n >= 5).sum())})")
print(f"   median gaps (h) of the five largest (gateway pair, day) groups: "
      f"{[round(x / H, 3) for x in D.groupby(['ga', 'gb', 'day']).gap.agg(['size', 'median']).sort_values('size', ascending=False).head(5)['median']]}")
print("done")
