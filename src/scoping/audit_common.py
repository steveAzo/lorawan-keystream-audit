"""Shared code for the keystream-reuse audit (LoED and Povalac and Kral captures), so every script applies the same rules.
Counts and distances only; no payload is decoded or printed.

Rules (one place, so a mutation test can change them once):
  frame         receptions with the same (DevAddr, FCnt, PHY size, PHY payload) within DUP_WIN s of the previous reception are one frame
                (duplicate receptions by several gateways or receivers, and duplicate log rows). Then, within the same (DevAddr, FCnt, size,
                PHY payload), a copy whose gateways are disjoint from the gateways already merged into the frame, less than XGW_WIN s after
                the frame's first reception, is merged into it (gateway-aware rule: a gateway hears one
                transmission once, and LoED's minor gateways log copies of one transmission with clocks 1 to 6 h apart). XGW_WIN = 0 turns
                the gateway-aware rule off. Where no PHY digest is stored the FRMPayload stands in for it; where no gateway is stored the rule
                cannot apply.
  counter test  a (DevAddr, FCnt, PHY size) triple whose frames span at least MIN_GAP s (any two frames, not only consecutive ones)
  pair          two frames of one triple at least MIN_GAP s apart whose FRMPayload have the same length (prefix=True also tests pairs of
                different length on their common prefix; the FRMPayload keystream depends on DevAddr, FCnt, direction and block index, not on
                length, so the prefix shares a keystream)
  related       pair with P(Binomial(8n, 0.5) <= k) < THRESH, k the differing bits, n the FRMPayload bytes compared (function related(),
                the only place the rule is coded; classify() and placebo() call it, and e21 checks its tail_p grid against it)
  identical     pair with equal FRMPayload at least IDENT_GAP s apart; equal FRMPayload closer than that is "identical-short" (unresolved:
                a retransmission and a restart cannot be told apart) and is counted separately, not as reuse
  confirmed     an address with at least one related or identical pair
Groups are examined on their first MAX_FRAMES frames in time order; the number of capped groups is reported.
Scripts that restate rules instead of calling this file: e20_ground_truth_sim.py (synthetic fleet: its own detector, 10-frame cap, no
merging, because it has no receptions or gateways), e15c_controls.py same-address control (its own pair sampling, same relatedness rule)."""
import math
import numpy as np
import pandas as pd

THRESH = 1e-6
MIN_GAP = 600
IDENT_GAP = 6 * 3600
DUP_WIN = 60
XGW_WIN = 6 * 3600
MAX_FRAMES = 80
COLLECT_GAP = DUP_WIN   # collection keeps triples whose receptions span >= this, a superset of the counter test (for the MIN_GAP sensitivity)
# An absorbed copy is scored at its head's time, so a window longer than IDENT_GAP can turn an identical-late pair (>= IDENT_GAP)
# into an identical-short one and remove a confirmation (the mutation test shows this on LoED for a window of 24 h or none).
assert XGW_WIN <= IDENT_GAP, "XGW_WIN must not exceed IDENT_GAP"


def tail_p(k, nb):
    """P(Binomial(nb, 0.5) <= k)."""
    if k < 0:
        return 0.0
    return sum(math.exp(math.lgamma(nb + 1) - math.lgamma(i + 1) - math.lgamma(nb - i + 1) - nb * math.log(2)) for i in range(min(k, nb) + 1))


_K = {}
def kstar(nb, thr=THRESH):
    """Largest k with P(Binomial(nb, .5) <= k) < thr, or -1 if none."""
    key = (nb, thr)
    if key not in _K:
        s = 0.0; k = -1
        for i in range(nb + 1):
            s += math.exp(math.lgamma(nb + 1) - math.lgamma(i + 1) - math.lgamma(nb - i + 1) - nb * math.log(2))
            if s < thr: k = i
            else: break
        _K[key] = k
    return _K[key]


def diff_bits(x, y):
    """Differing bits of two equal-length hex strings."""
    return (int(x, 16) ^ int(y, 16)).bit_count()


def related(x, y, thr=THRESH, k=None):
    """The relatedness rule, coded only here (classify and placebo call it): x, y equal-length hex strings; k their differing bits if
    already counted. Related when P(Binomial(4 len(x), 0.5) <= k) < thr."""
    if k is None: k = diff_bits(x, y)
    return k <= kstar(4 * len(x), thr)


def upper95(n):
    """95% upper bound on a per-pair rate after 0 hits in n pairs."""
    return 1 - 0.05 ** (1 / max(n, 1))


def frame_index(keys, t, gw=None, win=DUP_WIN, xgw_win=XGW_WIN):
    """Frames from receptions. keys: list of integer arrays that together identify a transmission (addr, fcnt, size, PHY digest);
    t: times; gw: gateway codes 0..62 or None. Returns (first, rows, gm, xgw): for each frame the index (into the input) of its first
    reception, the receptions merged, the gateway bitmask and the number of cross-gateway copies merged into it; frames in input key order."""
    n = len(t)
    if n == 0:
        z = np.zeros(0, np.int64); return z, z, z, z
    o = np.lexsort((t,) + tuple(k for k in reversed(keys)))
    ts = np.asarray(t)[o]
    samek = np.ones(n - 1, bool)
    for k in keys:
        x = np.asarray(k)[o]; samek &= x[1:] == x[:-1]; del x
    same = np.r_[False, samek & (np.diff(ts) <= win)]
    st = np.flatnonzero(~same)
    rows = np.diff(np.r_[st, n])
    if gw is None:
        gm = np.zeros(len(st), np.int64)
    else:
        g = np.asarray(gw)[o].astype(np.int64)
        if g.max() > 62: raise ValueError("more than 63 gateway codes; the bitmask does not fit")
        gm = np.bitwise_or.reduceat(np.left_shift(np.int64(1), g), st)
    head = np.arange(len(st))
    if xgw_win > 0 and gw is not None and len(st) > 1:
        sg = np.r_[False, samek[st[1:] - 1]]          # frame i continues the transmission key of frame i - 1
        tf = ts[st]; del ts
        hd, ml = {}, {}      # only frames that repeat a transmission key are touched (memory: 3.7 GB machine)
        for i in np.flatnonzero(sg).tolist():
            h = hd.get(i - 1, i - 1)
            mh = ml.get(h); mh = int(gm[h]) if mh is None else mh
            gi = int(gm[i])
            if (mh & gi) == 0 and tf[i] - tf[h] < xgw_win:
                hd[i] = h; ml[h] = mh | gi
        if hd: head[np.fromiter(hd.keys(), np.int64, len(hd))] = np.fromiter(hd.values(), np.int64, len(hd))
        for h, v in ml.items(): gm[h] = v
    keep = head == np.arange(len(st))
    rows_c = np.bincount(head, weights=rows, minlength=len(st)).astype(np.int64)
    xgw = np.bincount(head, minlength=len(st)) - 1
    return o[st][keep], rows_c[keep], gm[keep], xgw[keep]


def triple_key(a, f, s):
    """(DevAddr, FCnt, PHY size) packed into one int64, as in the collection scripts (FCnt < 2^16, size < 256)."""
    a, f, s = (np.asarray(x, np.int64) for x in (a, f, s))
    assert (f < 65536).all() and (s < 256).all()
    return (a << 24) | (f << 8) | s


def merge_receptions(d, win=DUP_WIN, xgw_win=XGW_WIN):
    """d: columns addr, fcnt, size, t, body, and optionally phy (PHY payload digest) and gw (gateway code); one row per reception.
    Returns one row per frame (columns addr, fcnt, size, t, body, rows, gm, xgw), sorted by t."""
    cols = ["addr", "fcnt", "size", "t", "body", "rows", "gm", "xgw"]
    if d.empty:
        return pd.DataFrame({c: pd.Series(dtype="object" if c == "body" else "float64" if c == "t" else "int64") for c in cols})
    tid = d.phy.to_numpy() if "phy" in d else pd.factorize(d.body)[0]
    gw = d.gw.to_numpy() if "gw" in d else None
    first, rows, gm, xgw = frame_index([triple_key(d.addr.to_numpy(), d.fcnt.to_numpy(), d["size"].to_numpy()), tid], d.t.to_numpy(), gw, win, xgw_win)
    x = d.iloc[first]
    out = pd.DataFrame({"addr": x.addr.to_numpy(), "fcnt": x.fcnt.to_numpy(), "size": x["size"].to_numpy(), "t": x.t.to_numpy(),
                        "body": x.body.to_numpy(), "rows": rows, "gm": gm, "xgw": xgw})
    return out.sort_values("t", kind="mergesort").reset_index(drop=True)


def uplink_frames(u, mask=None, win=DUP_WIN, xgw_win=XGW_WIN):
    """Frames from a pass-1 reception table (dict-like with addr, fcnt, size, t, phy, gw; sf optional). Returns a dict of frame arrays
    (addr, fcnt, size, t, rows, xgw, and sf of the first reception if present), in (addr, fcnt, size, phy, t) order."""
    g = (lambda k: u[k] if mask is None else u[k][mask])
    a, f, s, t = g("addr"), g("fcnt").astype(np.int64), g("size").astype(np.int64), g("t")
    first, rows, gm, xgw = frame_index([triple_key(a, f, s), g("phy")], t, g("gw"), win, xgw_win)
    out = dict(addr=a[first], fcnt=f[first], size=s[first], t=t[first], rows=rows, xgw=xgw)
    if "sf" in getattr(u, "files", u): out["sf"] = g("sf")[first]
    return out


def merged_uplinks(a, f, s, t, phy, gw=None, win=DUP_WIN, xgw_win=XGW_WIN):
    """Number of data-uplink frames (the frame rule above, no FRMPayload needed)."""
    return len(frame_index([triple_key(a, f, s), phy], t, gw, win, xgw_win)[0])


def pairs(t, bd, min_gap=MIN_GAP, max_frames=MAX_FRAMES, prefix=False):
    """Frame pairs of one triple (t, bd: times and FRMPayload hex of its frames in time order), on the first max_frames frames.
    Yields (i, j, gap, kind, k, nb): kind 'unequal' (lengths differ, prefix False), 'identical' (equal FRMPayload) or 'diff'
    (k differing bits over nb bits; with prefix=True pairs of different length are compared on their common prefix)."""
    m = min(len(bd), max_frames)
    for i in range(m):
        for j in range(i + 1, m):
            gap = abs(t[j] - t[i])
            if gap < min_gap: continue
            x, y = bd[i], bd[j]
            if len(x) != len(y):
                if not prefix: yield i, j, gap, "unequal", -1, 0; continue
                L = min(len(x), len(y)); x, y = x[:L], y[:L]
                if L == 0: continue
            elif x == y:
                yield i, j, gap, "identical", 0, 4 * len(x); continue
            yield i, j, gap, "diff", diff_bits(x, y), 4 * len(x)


def classify(t, bd, thr=THRESH, min_gap=MIN_GAP, ident_gap=IDENT_GAP, max_frames=MAX_FRAMES, prefix=False):
    """t, bd: times and bodies of the frames of one triple, in time order. Returns (related, identical, identical_short, unrelated, unequal_len, flagged).
    flagged: the counter test fires on the frames given (two frames >= min_gap apart). With prefix=True, unequal-length pairs are tested on
    their common prefix and counted in related or unrelated; unequal_len then counts the pairs so tested."""
    rel = ide = ids = unr = une = 0
    flagged = len(t) > 1 and (t[len(t) - 1] - t[0]) >= min_gap
    for i, j, gap, kind, k, nb in pairs(t, bd, min_gap, max_frames, prefix):
        if kind == "unequal": une += 1; continue
        if kind == "identical":
            if gap >= ident_gap: ide += 1
            else: ids += 1
            continue
        if len(bd[i]) != len(bd[j]): une += 1
        L = nb // 4
        if related(bd[i][:L], bd[j][:L], thr, k): rel += 1
        else: unr += 1
    return rel, ide, ids, unr, une, flagged


def analyse(frames, **kw):
    """frames: output of merge_receptions. One row per triple whose frames span >= min_gap s."""
    out = []
    if len(frames):   # keep only triples that can be flagged (span >= min_gap), so the group loop stays small when all frames are kept
        tg = frames.groupby(["addr", "fcnt", "size"], sort=False).t
        frames = frames[(tg.transform("max") - tg.transform("min")) >= kw.get("min_gap", MIN_GAP)]
    for (a, f, n), g in frames.groupby(["addr", "fcnt", "size"], sort=False):
        if len(g) < 2: continue
        t = g.t.to_numpy(); bd = list(g.body)
        rel, ide, ids, unr, une, flagged = classify(t, bd, **kw)
        if not flagged: continue
        out.append((int(a), int(f), int(n), int(g.rows.sum()), len(g), rel, ide, ids, unr, une, len(g) > kw.get("max_frames", MAX_FRAMES), (t.max() - t.min()) / 86400))
    return pd.DataFrame(out, columns=["addr", "fcnt", "size", "rows", "frames", "related", "identical", "ident_short", "unrelated", "unequal", "capped", "span_days"])


def placebo(frames, rng, per_group=60, reach=3, thr=THRESH):
    """Placebo: frames with the same FCnt and size from DIFFERENT addresses (different keystream by construction). One frame per
    (addr, fcnt, size); in each (fcnt, size) group up to per_group frames in random order, each compared with the next `reach`; pairs follow
    the pair rules (equal FRMPayload length, not identical). Returns (related, pairs)."""
    hit = tot = 0
    one = frames.drop_duplicates(["addr", "fcnt", "size"])
    for (f, n), g in one.groupby(["fcnt", "size"]):
        if g.addr.nunique() < 2: continue
        idx = rng.permutation(len(g))[:per_group]; a = g.addr.to_numpy()[idx]; bb = g.body.to_numpy()[idx]
        for i in range(len(idx) - 1):
            for j in range(i + 1, min(i + 1 + reach, len(idx))):
                if a[i] == a[j] or len(bb[i]) != len(bb[j]) or bb[i] == bb[j]: continue
                tot += 1; hit += related(bb[i], bb[j], thr)
    return hit, tot


LOED_FRAMES = "data/derived/reuse_frames_v3"
LOED_UPLINKS = "data/derived/loed_uplinks_v3.npz"


def loed_day_files(folder=LOED_FRAMES):
    """Day files in date order (names are dd_mm_yyyy)."""
    import glob, os
    p = glob.glob(folder + "/*.parquet")
    return sorted(p, key=lambda x: tuple(reversed(os.path.basename(x)[:-8].split("_"))))


def load_bucket(b, nbuckets=8, files=None, addrs=None, columns=None, xgw_win=XGW_WIN):
    """LoED receptions of addresses with addr % nbuckets == b (optionally only addrs), merged into frames."""
    files = files if files is not None else loed_day_files()
    parts = []
    for p in files:
        x = pd.read_parquet(p, columns=columns)
        x = x[x.addr % nbuckets == b]
        if addrs is not None: x = x[x.addr.isin(addrs)]
        if len(x): parts.append(x)
    d = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame({"addr": [], "fcnt": [], "size": [], "t": [], "body": []})
    return merge_receptions(d, xgw_win=xgw_win)


def capture_blocks(names):
    """Contiguous runs of daily files (names dd_mm_yyyy) as (start unix, end unix, days)."""
    import datetime as dt
    ds = sorted(dt.datetime.strptime(n, "%d_%m_%Y").replace(tzinfo=dt.timezone.utc) for n in names)
    blocks = []; s = p = ds[0]
    for d in ds[1:]:
        if (d - p).days > 1: blocks.append((s, p)); s = d
        p = d
    blocks.append((s, p))
    return [(a.timestamp(), b.timestamp() + 86400, (b - a).days + 1) for a, b in blocks]


def observed_days(t0, t1, blocks):
    """Days of [t0, t1] that fall inside the capture blocks."""
    return sum(max(0.0, min(t1, e) - max(t0, s)) for s, e, _ in blocks) / 86400


def label_groups(G):
    """Adds reuse (confirmed), examined (a testable pair) and unresolved (only identical-short pairs) columns."""
    G = G.copy()
    G["reuse"] = (G.related + G.identical) > 0
    G["examined"] = (G.related + G.identical + G.unrelated) > 0
    G["unresolved"] = ~G.examined & (G.ident_short > 0)
    return G


def counter_test(a, f, s, t, min_gap=MIN_GAP):
    """Counter test (no payload needed) on receptions or frames: the flagged triples, and the sort order and group bounds. Any two rows >= min_gap apart."""
    o = np.lexsort((t, s, f, a)); a, f, s, t = a[o], f[o], s[o], t[o]
    new = np.r_[True, (a[1:] != a[:-1]) | (f[1:] != f[:-1]) | (s[1:] != s[:-1])]
    st = np.flatnonzero(new); en = np.r_[st[1:], len(a)]
    span = t[en - 1] - t[st]
    flag = span >= min_gap
    return a[st][flag], f[st][flag], s[st][flag], st, en, o


def counter_resets(fcnt, step_max=64, wrap_tol=1024):
    """Counter resets in one address's frames (FCnt in time order): a drop of more than step_max that is not a 16-bit wrap (previous within
    wrap_tol of 65535 and new value below wrap_tol) and after which the counter goes on from the new value (next step 0..step_max), so that two
    devices interleaving behind one address are not counted. Returns (resets, drops of more than step_max, wraps)."""
    f = np.asarray(fcnt, np.int64)
    if len(f) < 2: return 0, 0, 0
    d = np.diff(f); drop = d < -step_max
    wrap = drop & (f[:-1] >= 65536 - wrap_tol) & (f[1:] < wrap_tol)
    nxt = np.r_[d[1:], -1]   # a drop at the last frame has no next step and is not counted
    cont = (nxt >= 0) & (nxt <= step_max)
    return int((drop & ~wrap & cont).sum()), int(drop.sum()), int(wrap.sum())


def join_stats(J, label, sims=300, seed=1, out=print):
    """DevNonce behaviour per DevEUI with >= 10 join requests. J: columns deveui, devnonce, t (duplicate receptions already merged).
    Repeats = n - distinct nonces; expectation and spread under uniform 16-bit nonces by simulation with the observed per-DevEUI counts."""
    J = J.sort_values(["deveui", "t"])
    rows = []
    for e, g in J.groupby("deveui"):
        if len(g) < 10: continue
        x = g.devnonce.to_numpy().astype(np.int64); dx = np.diff(x) % 65536; n = len(x)
        exp = n - 65536 * (1 - (1 - 1 / 65536) ** n)
        rows.append((e, n, n - len(set(x.tolist())), exp, float(np.mean(dx == 1)), float(np.mean((dx >= 1) & (dx <= 16))), float(np.mean(x == 0))))
    R = pd.DataFrame(rows, columns=["deveui", "n", "repeats", "expected", "step1", "step1_16", "zero_share"])
    if R.empty:
        out(f"{label}: no DevEUI with >= 10 join requests"); return R
    rng = np.random.default_rng(seed)
    tot = np.zeros(sims); per = np.zeros((sims, len(R)))
    for k in range(sims):
        for i, n in enumerate(R.n):
            v = rng.integers(0, 65536, int(n)); per[k, i] = n - len(np.unique(v))
        tot[k] = per[k].sum()
    sd_i = per.std(axis=0); R["z"] = (R.repeats - R.expected) / np.where(sd_i > 0, sd_i, np.nan)
    R["counter_strict"] = R.step1 >= .8; R["counter_loss_tolerant"] = R.step1_16 >= .8
    ex = R.repeats.sum() - R.expected.sum()
    top = (R.repeats - R.expected).sort_values(ascending=False)
    out(f"{label}: DevEUIs with >= 10 joins {len(R)}; DevNonce repeats (n - distinct) {int(R.repeats.sum())}, expected under uniform 16-bit nonces {R.expected.sum():.1f} "
        f"(simulated sd {tot.std():.1f}, max of {sims} simulations {int(tot.max())}); excess {ex:.1f}, top 5 DevEUIs hold {top.head(5).sum():.1f}")
    out(f"   DevEUIs with repeats more than 4 sd above expectation: {int((R.z > 4).sum())}; without the top 5 by excess: repeats {int(R.repeats.sum() - R.loc[top.head(5).index].repeats.sum())} "
        f"against {R.expected.sum() - R.loc[top.head(5).index].expected.sum():.1f} expected")
    out(f"   counter-like DevNonce: strict rule (>= 80% of steps equal +1) {int(R.counter_strict.sum())}; loss-tolerant rule (>= 80% of steps in +1..+16) {int(R.counter_loss_tolerant.sum())}; "
        f"constant zero nonce (>= 50% zero) {int((R.zero_share >= .5).sum())}; DevEUIs with at least one repeat {int((R.repeats > 0).sum())}")
    return R
