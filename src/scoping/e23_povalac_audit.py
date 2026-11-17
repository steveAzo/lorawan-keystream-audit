"""E23: the keystream-reuse audit, placebo and join census on the Povalac and Kral captures, city by city, with the rules of audit_common.py
(the same rules as E15b for LoED). Counts only; no payload is decoded or printed.
The main analysis keeps only the uplink concentrator (number 1) of the sniffer; data uplinks logged by the downlink concentrator are
image-frequency mirrors (Povalac et al., Section 4.7). Frames are keyed on the PHY digest; the counter test (any two frames at least MIN_GAP
apart) is reported on receptions and on frames with and without the gateway-aware merge; all pairs up to 80 frames per triple are tested.
Sensitivities: related pairs from 60 s, and unequal lengths compared on their common prefix. The placebo (audit_common.placebo) runs on all
frames and on frames of flagged triples. DevNonce repeats are compared with their expectation under uniform nonces. The same numbers on all
three concentrators are reported alongside. The three are concentrators of one sniffer (one antenna, one GNSS clock), so the gateway-aware
merge is not expected to act; the merge-off sensitivity also compares confirmed triples one by one.
Usage: python -I src/scoping/e23_povalac_audit.py <city> ..."""
import os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

UPLINK = 1   # concentrator number of the uplink concentrator (last hex digit of the receiver id)


def confirmed(d):
    G = C.label_groups(C.analyse(d))
    if G.empty: return set(), 0
    R = G[G.reuse]; return set(R.addr), int(R.frames.sum())


for city in sys.argv[1:]:
    fz = np.load(f"data/derived/povalac/{city}_frames.npz"); cc = fz["conc"]
    fr = {k: fz[k][cc == UPLINK] for k in ("addr", "fcnt", "size", "t", "phy", "gw")}
    a, f, s, t = fr["addr"], fr["fcnt"], fr["size"], fr["t"]
    F1 = C.uplink_frames(fr); F0 = C.uplink_frames(fr, xgw_win=0)
    byc = dict(zip(*[x.tolist() for x in np.unique(cc, return_counts=True)]))
    print(f"\n===== {city}: {len(a)} data-uplink receptions on the uplink concentrator (all concentrators of the sniffer {len(cc)}, by concentrator number {byc}), "
          f"{len(F0['addr'])} frames (same PHY payload within {C.DUP_WIN} s), {len(F1['addr'])} with the gateway-aware merge; {len(np.unique(a))} addresses; "
          f"first to last reception {(t.max()-t.min())/86400:.1f} days", flush=True)
    fl = {}
    for lab, (aa, ff_, ss, tt) in (("receptions", (a, f, s, t)), ("frames without the gateway-aware merge", (F0["addr"], F0["fcnt"], F0["size"], F0["t"])),
                                  ("frames with the gateway-aware merge (main)", (F1["addr"], F1["fcnt"], F1["size"], F1["t"]))):
        fa, ff, fs, *_ = C.counter_test(aa, ff_, ss, tt); fl[lab] = set(fa.tolist())
        print(f"counter test (any two rows of a triple >= {C.MIN_GAP} s apart) on {lab}: triples {len(fa)}, addresses {len(fl[lab])}")
    flagged_addr = fl["frames with the gateway-aware merge (main)"]
    RU = pd.read_parquet(f"data/derived/povalac/{city}_reuse.parquet"); RA = RU.drop(columns="conc"); RU = RA[RU.conc.to_numpy() == UPLINK]
    d = C.merge_receptions(RU)
    G = C.label_groups(C.analyse(d))
    if G.empty:
        print("no groups with FRMPayload"); continue
    E = G[G.examined]; R = G[G.reuse]
    ex_addr, conf = set(E.addr), set(R.addr)
    unres = set(G[G.unresolved].addr) - ex_addr
    print(f"triples with FRMPayload flagged {len(G)}; examined (a testable pair) {len(E)}; confirmed {len(R)}; capped at {C.MAX_FRAMES} frames {int(G.capped.sum())}; "
          f"unresolved (only identical pairs < {C.IDENT_GAP//3600} h apart) {int(G.unresolved.sum())} on {len(unres)} addresses not otherwise examined")
    print(f"confirmed addresses {len(conf)} = {len(conf)/len(np.unique(a)):.2%} of all addresses; of counter-flagged addresses {len(conf)}/{len(flagged_addr)} = {len(conf)/max(len(flagged_addr),1):.1%} "
          f"(on receptions {len(conf)}/{len(fl['receptions'])}); of examined addresses {len(conf)}/{len(ex_addr)} = {len(conf)/max(len(ex_addr),1):.1%}")
    if len(R):
        fr_r = R.groupby("addr").frames.sum().sort_values(ascending=False)
        print(f"frames in confirmed triples {int(fr_r.sum())} (receptions {int(R.rows.sum())}); top 1/5 addresses hold {fr_r.head(1).sum()/fr_r.sum():.1%}/{fr_r.head(5).sum()/fr_r.sum():.1%}; "
              f"triples with related pairs {int((R.related>0).sum())}, with identical-late pairs {int((R.identical>0).sum())}; addresses confirmed only by identical-late pairs "
              f"{len(conf - set(R[R.related>0].addr))}; frames in flagged triples with FRMPayload {int(G.frames.sum())}")
    print(f"triples with unequal-length pairs {int((G.unequal > 0).sum())}; flagged triples whose only pairs >= {C.MIN_GAP} s are unequal-length {int(((G.unequal > 0) & ~G.examined & (G.ident_short == 0)).sum())}")
    # all three concentrators
    Fa = C.uplink_frames({k: fz[k] for k in ("addr", "fcnt", "size", "t", "phy", "gw")}); faa, *_ = C.counter_test(Fa["addr"], Fa["fcnt"], Fa["size"], Fa["t"])
    conf_all, fr_all = confirmed(C.merge_receptions(RA))
    print(f"   all three concentrators: addresses {len(np.unique(fz['addr']))}, frames {len(Fa['addr'])}, counter-flagged addresses on frames {len(set(faa.tolist()))}, "
          f"confirmed addresses {len(conf_all)} (in one set only {len(conf_all ^ conf)}), frames in confirmed triples {fr_all}")
    G0 = C.label_groups(C.analyse(C.merge_receptions(RU, xgw_win=0)))
    k1 = set(zip(R.addr, R.fcnt, R["size"])); k0 = set(zip(G0[G0.reuse].addr, G0[G0.reuse].fcnt, G0[G0.reuse]["size"])) if len(G0) else set()
    print(f"   gateway-aware merge off, triple by triple: confirmed triples {len(k0)} against {len(k1)}; removed by the merge {len(k0 - k1)}, added {len(k1 - k0)}")
    for lab, kw, dd in (("gateway-aware merge off", {}, C.merge_receptions(RU, xgw_win=0)),
                        ("related pairs from 60 s (identical pairs still >= 6 h)", {"min_gap": 60}, d),
                        ("unequal-length pairs tested on their common prefix", {"prefix": True}, d)):
        G2 = C.label_groups(C.analyse(dd, **kw)); c2 = set(G2[G2.reuse].addr)
        print(f"   sensitivity, {lab}: confirmed addresses {len(c2)} (not confirmed by the main rule {len(c2 - conf)}, lost {len(conf - c2)}); "
              f"frames in confirmed triples {int(G2[G2.reuse].frames.sum())}")
    # placebo: different addresses, same FCnt and size, same body length; one frame per (addr, fcnt, size)
    keys = set(zip(G.addr, G.fcnt, G["size"]))
    dfl = d[[k in keys for k in zip(d.addr, d.fcnt, d["size"])]]
    for lab, dd in (("frames of flagged triples", dfl), ("all frames", d)):
        hit, tot = C.placebo(dd, np.random.default_rng(1))
        print(f"placebo on {lab} (different addresses, same FCnt and size): {hit} related of {tot} pairs; 95% upper bound on the per-pair rate {C.upper95(tot):.1e}")
    try:
        J = pd.read_parquet(f"data/derived/povalac/{city}_joins.parquet")
        n = J.groupby("deveui").size()
        J["day"] = (J.t // 86400).astype(int); pdv = J.groupby(["deveui", "day"]).size()
        print(f"join requests {len(J)} (duplicate receptions merged), DevEUIs {J.deveui.nunique()}, max per DevEUI {int(n.max()) if len(n) else 0}; "
              f"DevEUI-days with >= 20 joins: {int((pdv>=20).sum())}, max per day {int(pdv.max()) if len(pdv) else 0}")
        C.join_stats(J, f"{city} DevNonce")
    except Exception as e:
        print("joins:", e)
print("done")
