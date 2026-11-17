"""E18: two mechanism gates for the keystream-reuse finding (LoED), on the confirmed addresses of E15b.
Gate A (detector): the counter-rollback test against the ciphertext test, on two stated definitions of the counter test's flagged set:
  (i) all addresses with a triple seen twice >= 10 min apart (no payload needed), (ii) addresses with an examined triple (a testable pair).
Gate B (retrofit): per confirmed address, reset cadence over OBSERVED days (the capture is two blocks; the gap between them is not counted) and the airtime
of three fixes. Airtime: Semtech formula, 125 kHz, CR 4/5, 8-symbol preamble; join request 23 B; join accept 17 B at the uplink SF.
Input: the pass-1 table of collect_loed.py (one row per reception). Gate A on frames with the gateway-aware merge (main) and without it;
Gate B on frames built by audit_common (same PHY payload, gateway-aware merge) and resets counted by
audit_common.counter_resets (a 16-bit wrap and two devices interleaving behind one address are not resets); results are per address. Writes results/e18_devices.csv (per address, no address column) and data/derived/e18_devices_addr.csv (with
addresses; kept local). Usage: python -I src/scoping/e18_mechanism_gates.py"""
import math, os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

G = pd.read_parquet("results/e15_groups.parquet")
conf = set(int(x) for x in G[G.reuse].addr); ex = set(int(x) for x in G[G.examined].addr)
u = np.load(C.LOED_UPLINKS)
a, f, s, t = u["addr"], u["fcnt"].astype(np.int64), u["size"].astype(np.int64), u["t"]
for lab, xw in (("without the gateway-aware merge", 0), ("with the gateway-aware merge (main)", C.XGW_WIN)):
    Fr = C.uplink_frames(u, xgw_win=xw)
    fa, *_ = C.counter_test(Fr["addr"], Fr["fcnt"], Fr["size"], Fr["t"]); flag = set(fa.tolist())
    print(f"Gate A: (i) counter-flagged addresses, frames {lab}: {len(flag)}, confirmed {len(conf)} (all flagged: {conf <= flag}), precision {len(conf)/len(flag):.1%}")
print(f"        (ii) addresses with an examined triple {len(ex)}, confirmed {len(conf)}, precision {len(conf)/len(ex):.1%}")
print(f"        examined triples {int(G.examined.sum())}, confirmed {int(G.reuse.sum())}, precision {G.reuse.sum()/G.examined.sum():.1%}")
fr_c = int(G[G.examined].frames.sum()); fr_k = int(G[G.reuse].frames.sum())
print(f"        frames in examined triples {fr_c}, in confirmed triples {fr_k} (the counter test, on triples it can examine, flags {fr_c/fr_k:.1f} times the confirmed frames)")
blocks = C.capture_blocks(list(u["names"]))
def air(pl, sf, bw=125e3):
    de = 1 if sf >= 11 else 0; ts = 2**sf / bw
    n = 8 + max(math.ceil((8*pl - 4*sf + 28 + 16) / (4*(sf - 2*de))) * 5, 0)
    return (8 + 4.25 + n) * ts
def slack(pl, sf):
    a0 = air(pl, sf); k = 0
    while air(pl + k + 1, sf) == a0: k += 1
    return k
Fr = C.uplink_frames(u, mask=np.isin(a, list(conf)))
a, f, t, sf, sz = Fr["addr"], Fr["fcnt"], Fr["t"], Fr["sf"], Fr["size"]
oo = np.lexsort((t, a)); a, f, t, sf, sz = a[oo], f[oo], t[oo], sf[oo], sz[oo]
rows = []; drops = wraps = 0
st = np.r_[0, np.flatnonzero(np.diff(a)) + 1]; en = np.r_[st[1:], len(a)]
for i, j in zip(st, en):
    ff_, tt, s_, z = f[i:j], t[i:j], sf[i:j], sz[i:j]
    if len(ff_) < 20: continue
    resets, dr, wr = C.counter_resets(ff_); drops += dr; wraps += wr
    days = max(C.observed_days(tt.min(), tt.max(), blocks), 1e-9)
    sfm = int(np.median(s_[s_ > 0])) if (s_ > 0).any() else 7; pl = int(np.median(z))
    a_up = air(pl, sfm); per_day = len(ff_) / days; a_join = air(23, sfm) + air(17, sfm)
    k = max(1, len(z) // 300); smp = [(int(p), int(q)) for p, q in zip(z[::k], s_[::k]) if q > 0]
    sl = np.array([slack(p, q) for p, q in smp])
    rows.append(dict(addr=int(a[i]), frames=len(ff_), days=days, resets=resets, resets_per_day=resets / days, sf=sfm, pl=pl,
                     rejoin_share=resets / days * a_join / (a_up * per_day), iv8_share=(air(pl + 8, sfm) - a_up) / a_up,
                     slack_ge2=float((sl >= 2).mean()), epoch2_cost=float(np.mean([air(p + 2, q) - air(p, q) for p, q in smp])) / a_up))
R = pd.DataFrame(rows); r = R[R.resets > 0]
print(f"\nGate B: confirmed addresses with >= 20 frames: {len(R)}, with at least one counter reset: {len(r)}; counter drops of more than 64: {drops}, "
      f"of which 16-bit wraps {wraps}; counted as resets {int(R.resets.sum())}")
print("resets per observed day (median / p90 / max): %.3f / %.2f / %.1f" % (r.resets_per_day.median(), r.resets_per_day.quantile(.9), r.resets_per_day.max()))
print("SF of these addresses:", R.sf.value_counts().sort_index().to_dict(), " PHY size top:", R.pl.value_counts().head(4).to_dict())
for name, c in (("rejoin on every boot", "rejoin_share"), ("8-byte random IV in payload", "iv8_share"), ("2-byte epoch with no slack use", "epoch2_cost")):
    print(f"airtime added, share of the address's uplink airtime, {name}: median {r[c].median():.2%}  p90 {r[c].quantile(.9):.2%}  mean {r[c].mean():.2%}")
print("frames with slack >= 2 B: median across addresses %.0f%%" % (100 * R.slack_ge2.median()))
os.makedirs("data/derived", exist_ok=True)
R.to_csv("data/derived/e18_devices_addr.csv", index=False)   # with addresses: stays local (data/ is not published)
R.drop(columns="addr").to_csv("results/e18_devices.csv", index=False)
print("done")
