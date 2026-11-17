"""E26: MIC-only default-key check on the Povalac and Kral captures (Brno and Vienna), as a real-data ground truth for the ciphertext test.
Povalac et al. (Sensors 23 (2023) 7333, Section 4.6) report ABP devices that use Semtech's published default key 2B7E1516... as both session
keys (15.5% of valid Brno packets, 0.2% in Vienna) and the all-zero key in Brno and Vienna. For such a device one key gives one keystream, so
two frames with the same DevAddr and the same 32-bit FCnt certainly reuse a keystream.
Method: for every data uplink on the uplink concentrator (MHDR valid, as parse_povalac.py), the LoRaWAN 1.0.x uplink MIC
(AES-CMAC over B0 | MHDR..FRMPayload, first 4 bytes) is computed with each published key, as NwkSKey, and compared with the frame's MIC; FCnt's
upper 16 bits are taken as 0, and for frames that fail on an address where the key verified at least one frame, as 1 to 15; on an address
where no frame verifies, its first 3 frames are also tried with upper bits 1 to 255 (a device whose 32-bit counter stayed above 65535). Only the MIC is
computed: no payload is decrypted, no keystream is formed, and no address is printed.
Ground truth on a triple (DevAddr, 16-bit FCnt, PHY size) whose frames all verify under a default key ("decidable"): keystream reuse is
certain if two frames at least MIN_GAP s apart verify under the same key with the same 32-bit FCnt, and absent otherwise. Test: the triple is
confirmed by the ciphertext test of audit_common (the same frames as e23). Reported: recall, and precision on decidable triples; confirmed
triples that are not decidable (some frame verifies under no default key: another device or key behind the address) are counted apart.
Usage (from the repository root): python -I src/scoping/e26_default_key_mic.py <log.zip> <city_log> ...   (e.g. 07_Brno.log 05_Wien.log)"""
import os, sys, zipfile
import numpy as np, pandas as pd
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "data"))
import audit_common as C
from parse_povalac import rows, digest
import base64

KEYS = {1: ("Semtech default key", bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")), 2: ("all-zero key", bytes(16))}
UPLINK = 1


def mic(key, r, fc32):
    msg = r[:-4]
    b0 = bytes([0x49, 0, 0, 0, 0, 0]) + r[1:5] + fc32.to_bytes(4, "little") + bytes([0, len(msg)])
    c = CMAC(algorithms.AES(key)); c.update(b0 + msg)
    return c.finalize()[:4] == r[-4:]


def run(zf, member):
    city = member.split(".")[0].split("_", 1)[1].lower()
    A, F, S, T, H, GW, R = [], [], [], [], [], [], []
    gw_code = {}
    for t, b64, datr, g in rows(zf, member):
        if int(g[-1:], 16) != UPLINK: continue
        r = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        if (r[0] >> 5) not in (2, 4) or len(r) < 12 or r[0] & 0x1F: continue
        A.append(int.from_bytes(r[1:5], "little")); F.append(int.from_bytes(r[6:8], "little")); S.append(len(r)); T.append(t)
        H.append(digest(r)); GW.append(gw_code.setdefault(g, len(gw_code))); R.append(r)
    n = len(R); key = np.zeros(n, np.int8); up = np.full(n, -1, np.int16)
    for i, r in enumerate(R):
        fc = F[i]
        for kid, (_, k) in KEYS.items():
            if mic(k, r, fc): key[i] = kid; up[i] = 0; break
    a = np.array(A, np.int64)
    for kid, (_, k) in KEYS.items():   # higher 32-bit counters on addresses where the key verified a frame
        ka = set(a[key == kid].tolist())
        for i in np.flatnonzero((key == 0) & np.isin(a, list(ka))).tolist():
            for hi in range(1, 16):
                if mic(k, R[i], (hi << 16) | F[i]): key[i] = kid; up[i] = hi; break
    seen = set(a[key > 0].tolist()); tried = {}
    for i in range(n):          # addresses with no verified frame: first 3 frames, upper bits 1..255
        ai = A[i]
        if ai in seen or tried.get(ai, 0) >= 3: continue
        tried[ai] = tried.get(ai, 0) + 1
        for kid, (_, k) in KEYS.items():
            hi = next((h for h in range(1, 256) if mic(k, R[i], (h << 16) | F[i])), None)
            if hi is not None: key[i] = kid; up[i] = hi; seen.add(ai); break
    late = sorted(set(a[(key > 0)].tolist()) - set(a[(key > 0) & (up == 0)].tolist()))
    for i in np.flatnonzero((key == 0) & np.isin(a, late)).tolist():   # all frames of such addresses, upper bits 1..255
        for kid, (_, k) in KEYS.items():
            hi = next((h for h in range(1, 256) if mic(k, R[i], (h << 16) | F[i])), None)
            if hi is not None: key[i] = kid; up[i] = hi; break
    del R
    f, s, t, ph, gw = (np.array(x, d) for x, d in ((F, np.int64), (S, np.int64), (T, np.float64), (H, np.int64), (GW, np.int8)))
    first, *_ = C.frame_index([C.triple_key(a, f, s), ph], t, gw)
    Fr = pd.DataFrame({"addr": a[first], "fcnt": f[first], "size": s[first], "t": t[first], "key": key[first], "up": up[first]})
    print(f"\n===== {city}: {n} data uplinks on the uplink concentrator, {len(Fr)} frames, {Fr.addr.nunique()} addresses", flush=True)
    for kid, (lab, _) in KEYS.items():
        m = key == kid
        print(f"   receptions whose MIC verifies with the {lab}: {int(m.sum())} ({m.mean():.1%}), of which with FCnt above 65535: {int((m & (up > 0)).sum())}")
    print(f"   receptions verifying with both keys: 0 by construction (the first key that verifies is kept)")
    print(f"   addresses whose frames verify only with FCnt above 65535 (upper bits 1 to 255): {len(late)}")
    # per address
    pa = Fr.groupby("addr").agg(n=("key", "size"), k1=("key", lambda x: int((x == 1).sum())), k2=("key", lambda x: int((x == 2).sum())))
    pa["dk"] = pa.k1 + pa.k2
    DK = set(pa[pa.dk > 0].index)
    for kid, col in ((1, "k1"), (2, "k2")):
        q = pa[pa[col] > 0]
        print(f"   addresses with at least one frame verifying under the {KEYS[kid][0]}: {len(q)}; frames on them {int(q.n.sum())}, of which verify {int(q[col].sum())} "
              f"({q[col].sum() / max(q.n.sum(), 1):.1%}); addresses with every frame verifying {int((q[col] == q.n).sum())}")
    print(f"   default-key addresses (either key): {len(DK)} of {len(pa)} ({len(DK) / len(pa):.1%}); their frames {int(pa.loc[list(DK)].n.sum())} of {len(Fr)} "
          f"({pa.loc[list(DK)].n.sum() / len(Fr):.1%})")
    # ciphertext test on the same frames as e23 (uplink concentrator)
    RU = pd.read_parquet(f"data/derived/povalac/{city}_reuse.parquet"); RU = RU[RU.conc.to_numpy() == UPLINK].drop(columns="conc")
    G = C.label_groups(C.analyse(C.merge_receptions(RU)))
    conf = set(G[G.reuse].addr)
    ctrip = set(zip(G[G.reuse].addr, G[G.reuse].fcnt, G[G.reuse]["size"]))
    print(f"   ciphertext test: confirmed addresses {len(conf)}; of them default-key addresses {len(conf & DK)}; default-key addresses not confirmed {len(DK - conf)}; "
          f"confirmed addresses without a default key {len(conf - DK)}")
    if not DK:
        print("   no default-key address: no ground truth for the ciphertext test in this capture"); return
    Rc = G[G.reuse]; fk = int(Rc[Rc.addr.isin(DK)].frames.sum())
    print(f"   frames in confirmed triples on default-key addresses: {fk} of {int(Rc.frames.sum())} ({fk / max(Rc.frames.sum(), 1):.1%})")
    # ground truth on triples of default-key addresses
    X = Fr[Fr.addr.isin(DK)]
    tg = X.groupby(["addr", "fcnt", "size"]).t
    X = X[(tg.transform("max") - tg.transform("min")) >= C.MIN_GAP]     # triples the counter test flags
    rows_ = []
    for (aa, ff, ss), g in X.groupby(["addr", "fcnt", "size"], sort=False):
        dec = bool((g.key > 0).all())
        truth = False
        for _, h in g[g.key > 0].groupby(["key", "up"]):
            if h.t.max() - h.t.min() >= C.MIN_GAP: truth = True; break
        rows_.append((aa, ff, ss, dec, truth, (aa, ff, ss) in ctrip))
    Q = pd.DataFrame(rows_, columns=["addr", "fcnt", "size", "decidable", "truth", "confirmed"])
    D = Q[Q.decidable]
    tp = int((D.truth & D.confirmed).sum()); fp = int((~D.truth & D.confirmed).sum()); fn = int((D.truth & ~D.confirmed).sum()); tn = int((~D.truth & ~D.confirmed).sum())
    print(f"   counter-flagged triples on default-key addresses: {len(Q)}; decidable (every frame verifies under a default key) {len(D)}")
    print(f"   decidable triples: keystream reuse certain {int(D.truth.sum())}, absent (frames >= {C.MIN_GAP} s apart differ in key or 32-bit FCnt) {int((~D.truth).sum())}")
    print(f"   ciphertext test on decidable triples: confirmed and reuse {tp}, confirmed without reuse {fp}, reuse not confirmed {fn}, neither {tn}; "
          f"triple recall {tp / max(tp + fn, 1):.1%}, triple precision {tp / max(tp + fp, 1):.1%}" + ("" if tp + fp else " (no confirmed decidable triple)")
          + ("" if (~D.truth).any() else "; no decidable triple without reuse exists, so precision is tested only as false confirmations among the reuse triples, not against negatives"))
    nd = Q[~Q.decidable]
    print(f"   triples not decidable: {len(nd)}, of which confirmed {int(nd.confirmed.sum())}")
    ta = set(D[D.truth].addr); ca = set(D[D.confirmed].addr); tpa = set(D[D.truth & D.confirmed].addr)
    print(f"   addresses (decidable triples): with certain reuse {len(ta)}, of which confirmed {len(ta & conf)} (address recall {len(ta & conf) / max(len(ta), 1):.1%}); "
          f"confirmed on a decidable triple {len(ca)}, of which with a confirmed triple of certain reuse {len(tpa)} (address precision {len(tpa) / max(len(ca), 1):.1%})")
    # why reuse goes unconfirmed: the first frames' pairs (no payload decoded; only the stored lengths and pair kinds)
    if fn:
        miss = set(zip(D[D.truth & ~D.confirmed].addr, D[D.truth & ~D.confirmed].fcnt, D[D.truth & ~D.confirmed]["size"]))
        Gm = G[[k in miss for k in zip(G.addr, G.fcnt, G["size"])]]
        print(f"   reuse not confirmed, by what the ciphertext test saw: no FRMPayload or not in its flagged set {fn - len(Gm)}; only unequal-length pairs "
              f"{int(((Gm.unequal > 0) & ~Gm.examined & (Gm.ident_short == 0)).sum())}; only identical pairs under {C.IDENT_GAP // 3600} h {int(Gm.unresolved.sum())}; "
              f"examined but unrelated {int((Gm.examined & ~Gm.reuse).sum())}")


if __name__ == "__main__":
    zf = zipfile.ZipFile(sys.argv[1])
    for m in sys.argv[2:]: run(zf, m)
    print("done")
