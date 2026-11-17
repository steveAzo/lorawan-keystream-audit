"""Parse the Povalac and Kral LoRaWAN sniffer logs (Zenodo 10.5281/zenodo.8090619) for the keystream-reuse audit.
Each log line is '0x<gateway>: {"rxpk":[{... "tmms":<GPS ms>, "stat":1, "size":N, "data":"<base64 PHY payload>"}]}'.
Pass 1 reads (DevAddr, FCnt, size, time) of CRC-valid data uplinks (MHDR mtype 010 or 100) and reports the triples the counter test of
audit_common flags; pass 2 keeps the FRMPayload of all data uplinks, so the placebo can use all frames (the audit selects flagged triples itself).
The receiver id (the 0x<gateway> prefix, coded 0..n-1 per city) and an 8-byte BLAKE2b digest of the PHY payload are stored with every
reception. Data uplinks whose MHDR has RFU bits set or Major not 0 (invalid LoRaWAN frames, Povalac et al., Section 4.8) are dropped in both passes, and the concentrator number (last hex digit of the receiver id: 1 uplink, 2 downlink with
IQ inverted, whose data uplinks are image-frequency mirrors, 3 RX2; Povalac et al., Table 2) is stored as column conc, so the audit can keep the uplink
concentrator only. The three concentrators belong to one sniffer (one antenna, one GNSS clock).
Join requests (mtype 000, 23 bytes): duplicate receptions (same DevEUI and DevNonce within 10 s) are merged, as in E16 for LoED.
Output: data/derived/povalac/<city>_reuse.parquet (all data uplinks with FRMPayload), <city>_joins.parquet, <city>_frames.npz. One row per reception; receptions are merged into frames by the audit.
Usage: python -I src/data/parse_povalac.py <log.zip> <city_log_name> ... ; run from the repository root."""
import base64, hashlib, json, os, re, sys, zipfile
from array import array
import numpy as np, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scoping"))
from audit_common import counter_test

GPS_TO_UNIX = 315964800 - 18
LINE = re.compile(rb'^0x([0-9A-Fa-f]+): (\{.*\})\s*$')

def rows(zf, member):
    with zf.open(member) as fh:
        for raw in fh:
            m = LINE.match(raw)
            if not m: continue
            try:
                j = json.loads(m.group(2))
            except ValueError:
                continue
            for p in j.get("rxpk", []):
                if p.get("stat") == 1 and "data" in p and "tmms" in p:
                    yield p["tmms"] / 1000 + GPS_TO_UNIX, p["data"], p.get("datr", ""), m.group(1).lower()

def digest(r):
    return int.from_bytes(hashlib.blake2b(r, digest_size=8).digest(), "little", signed=True)

def run(zf, member, out_prefix):
    A, F, S, T, H, GW, CC = array("q"), array("q"), array("q"), array("d"), array("q"), array("b"), array("b")
    joins = []; n_all = 0; gw_code = {}; n_bad = 0
    for t, b64, datr, g in rows(zf, member):
        r = base64.b64decode(b64 + "=" * (-len(b64) % 4)); n_all += 1
        mt = r[0] >> 5
        if mt == 0 and len(r) == 23:
            joins.append((t, datr, r[1:9][::-1].hex(), r[9:17][::-1].hex(), int.from_bytes(r[17:19], "little")))
        elif mt in (2, 4) and len(r) >= 12:
            if r[0] & 0x1F: n_bad += 1; continue   # MHDR RFU bits or Major not 0
            A.append(int.from_bytes(r[1:5], "little")); F.append(int.from_bytes(r[6:8], "little")); S.append(len(r)); T.append(t)
            H.append(digest(r)); GW.append(gw_code.setdefault(g, len(gw_code))); CC.append(int(g[-1:], 16))
    a, f, s, t, ph, gw, cc = (np.frombuffer(x, dtype=d) for x, d in ((A, np.int64), (F, np.int64), (S, np.int64), (T, np.float64), (H, np.int64), (GW, np.int8), (CC, np.int8)))
    print(member, "CRC-valid frames:", n_all, " data uplinks:", len(a), " dropped for MHDR RFU or Major not 0:", n_bad, " join requests:", len(joins),
          " addresses:", len(np.unique(a)), " concentrators:", len(gw_code), " data uplinks by concentrator number:",
          dict(zip(*[x.tolist() for x in np.unique(cc, return_counts=True)])), flush=True)
    np.savez_compressed(out_prefix + "_frames.npz", addr=a, fcnt=f, size=s, t=t, phy=ph, gw=gw, conc=cc)
    J = pd.DataFrame(joins, columns=["t", "datr", "joineui", "deveui", "devnonce"]).sort_values(["deveui", "devnonce", "t"])
    dup = (J.deveui == J.deveui.shift()) & (J.devnonce == J.devnonce.shift()) & ((J.t - J.t.shift()) < 10)
    print("  join requests:", len(J), " duplicate receptions merged:", int(dup.sum()), flush=True)
    J[~dup].sort_values(["deveui", "t"]).to_parquet(out_prefix + "_joins.parquet", index=False)
    fa, ff, fs, *_ = counter_test(a, f, s, t)
    print("  repeated triples:", len(np.unique((fa << 24) | (ff << 8) | fs)), flush=True)
    kept = []
    for t_, b64, datr, g in rows(zf, member):
        r = base64.b64decode(b64 + "=" * (-len(b64) % 4)); mt = r[0] >> 5
        if mt in (2, 4) and len(r) >= 12 and not r[0] & 0x1F:
            h = 8 + (r[5] & 0x0F)
            if len(r) > h + 5:
                kept.append((int.from_bytes(r[1:5], "little"), int.from_bytes(r[6:8], "little"), len(r), t_, r[h + 1:-4].hex(), digest(r), gw_code[g], int(g[-1:], 16)))
    pd.DataFrame(kept, columns=["addr", "fcnt", "size", "t", "body", "phy", "gw", "conc"]).astype({"gw": "int8", "conc": "int8"}).to_parquet(out_prefix + "_reuse.parquet", index=False)
    print("  frames kept for ciphertext test:", len(kept), flush=True)

if __name__ == "__main__":
    zf = zipfile.ZipFile(sys.argv[1]); os.makedirs("data/derived/povalac", exist_ok=True)
    for name in sys.argv[2:]:
        run(zf, name, "data/derived/povalac/" + name.split(".")[0].split("_", 1)[1].lower())
    print("done", flush=True)
