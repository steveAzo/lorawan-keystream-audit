"""Collect LoED data uplinks for the keystream-reuse audit straight from the raw zip, in two passes.
DevAddr, FCnt and message type are read from the PHY payload bytes, not from the CSV columns (one CSV address value is a placeholder for undecoded rows).
Pass 1: every CRC-valid data uplink (MHDR type 010 or 100, at least 12 bytes): DevAddr, FCnt, PHY size, time, SF, has-FRMPayload flag, day index,
        gateway code and an 8-byte BLAKE2b digest of the whole PHY payload (equality only)
        -> data/derived/loed_uplinks_v3.npz (one row per reception; gateway identifiers kept locally in 'gateways', codes are their indices).
Pass 2: FRMPayload (hex, no MIC), PHY digest and gateway code of the receptions whose (DevAddr, FCnt, size) triple has receptions at least
        COLLECT_GAP s apart (60 s, a superset of the 600 s counter test, so the minimum-gap sensitivity can be run)
        -> data/derived/reuse_frames_v3/<day>.parquet. Payload bodies stay local and are never printed.
        A manifest (keys.json) records the hash of the collected key set and a hash of the collection
        spec (COLLECT_GAP, the stored column list with dtypes, and the digest); day files made under a different key set or spec are
        deleted before collecting, so a rerun after a rule change never reuses old files. A manifest without the spec hash counts as different.
FCnt is stored as a 4-byte integer on every platform.
Usage: python -I src/data/collect_loed.py <LoED_full.zip> [pass1|pass2|both]; run from the repository root."""
import base64, glob, hashlib, json, os, sys, zipfile
from array import array
import numpy as np, pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scoping"))
from audit_common import counter_test, COLLECT_GAP, LOED_UPLINKS as OUT1, LOED_FRAMES as OUT2

COLS = ["time", "physical_payload", "crc_status", "spreading_factor", "gateway"]
OUT2_COLS = {"addr": "int64", "fcnt": "int64", "size": "int64", "t": "float64", "body": "str", "phy": "int64", "gw": "int8"}   # pass-2 columns
DIGEST = "blake2b-8 of the whole PHY payload, little-endian signed int64"
SPEC_HASH = hashlib.sha256(json.dumps({"collect_gap": COLLECT_GAP, "columns": OUT2_COLS, "digest": DIGEST}, sort_keys=True).encode()).hexdigest()


def day_files(z):
    return sorted(x for x in z.namelist() if x.endswith(".csv") and not x.startswith("__MACOSX"))


def chunks(z, name):
    with z.open(name) as fh:
        for c in pd.read_csv(fh, usecols=COLS, dtype=str, chunksize=100_000):
            c = c[(c.crc_status == "1") & c.physical_payload.notna() & c.time.notna()]
            if c.empty: continue
            t = ((pd.to_datetime(c.time, utc=True, format="ISO8601", errors="coerce") - pd.Timestamp("1970-01-01", tz="UTC")) / pd.Timedelta(seconds=1)).to_numpy()
            yield c, t


def frame(p):
    r = base64.b64decode(p + "=" * (-len(p) % 4))
    if len(r) < 12 or (r[0] >> 5) not in (2, 4): return None
    return r


def digest(r):
    return int.from_bytes(hashlib.blake2b(r, digest_size=8).digest(), "little", signed=True)


def pass1(z):
    A, F, S, T, B, SF, D, GW, H = array("q"), array("i"), array("h"), array("d"), array("b"), array("b"), array("h"), array("b"), array("q")
    assert F.itemsize == 4
    gw_code = {}; bad_t = 0
    for di, name in enumerate(day_files(z)):
        for c, t in chunks(z, name):
            for p, tt, sf, g in zip(c.physical_payload, t, c.spreading_factor, c.gateway):
                r = frame(p)
                if r is None: continue
                if tt != tt: bad_t += 1; continue
                h = 8 + (r[5] & 0x0F)
                A.append(int.from_bytes(r[1:5], "little")); F.append(int.from_bytes(r[6:8], "little")); S.append(len(r)); T.append(float(tt))
                B.append(1 if len(r) > h + 5 else 0); D.append(di); GW.append(gw_code.setdefault(str(g), len(gw_code))); H.append(digest(r))
                try: SF.append(int(float(sf)))
                except (TypeError, ValueError): SF.append(-1)
        print("pass1", di, os.path.basename(name), len(A), flush=True)
    if len(gw_code) > 63: sys.exit("more than 63 gateways")
    np.savez_compressed(OUT1, addr=np.frombuffer(A, np.int64), fcnt=np.frombuffer(F, np.int32), size=np.frombuffer(S, np.int16),
                        t=np.frombuffer(T, np.float64), body=np.frombuffer(B, np.int8), sf=np.frombuffer(SF, np.int8), day=np.frombuffer(D, np.int16),
                        gw=np.frombuffer(GW, np.int8), phy=np.frombuffer(H, np.int64),
                        names=np.array([os.path.basename(n)[:-4] for n in day_files(z)]), gateways=np.array(list(gw_code)))
    print("pass1 receptions", len(A), "rows with unparseable time", bad_t, "gateways", len(gw_code), flush=True)


def pass2(z):
    u = np.load(OUT1)
    assert len(u["fcnt"]) == len(u["addr"]) == len(u["t"]), "pass-1 arrays differ in length"
    m = u["body"] == 1
    a, f, s, t = u["addr"][m], u["fcnt"][m].astype(np.int64), u["size"][m].astype(np.int64), u["t"][m]
    fa, ff, fs, *_ = counter_test(a, f, s, t, min_gap=COLLECT_GAP)
    keys = np.unique((fa << 24) | (ff << 8) | fs); del a, f, s, t
    gw_code = {g: i for i, g in enumerate(u["gateways"].tolist())}; del u
    kh = hashlib.sha256(keys.tobytes()).hexdigest()
    print("pass2 triples with FRMPayload and receptions >=", COLLECT_GAP, "s apart:", len(keys), "key hash", kh[:16], flush=True)
    os.makedirs(OUT2, exist_ok=True)
    man = os.path.join(OUT2, "keys.json")
    old = json.load(open(man)) if os.path.exists(man) else None
    if old is None or old.get("key_hash") != kh or old.get("spec_hash") != SPEC_HASH:
        stale = glob.glob(os.path.join(OUT2, "*.parquet"))
        for p in stale: os.remove(p)
        print("pass2: manifest missing or different; removed", len(stale), "old day files", flush=True)
        json.dump({"key_hash": kh, "spec_hash": SPEC_HASH, "collect_gap": COLLECT_GAP, "columns": OUT2_COLS, "triples": int(len(keys))}, open(man, "w"))
    for name in day_files(z):
        p = os.path.join(OUT2, os.path.basename(name)[:-4] + ".parquet")
        if os.path.exists(p): continue
        rows = []
        for c, t in chunks(z, name):
            for pl, tt, g in zip(c.physical_payload, t, c.gateway):
                r = frame(pl)
                if r is None or tt != tt: continue
                h = 8 + (r[5] & 0x0F)
                if len(r) <= h + 5: continue
                k = (int.from_bytes(r[1:5], "little") << 24) | (int.from_bytes(r[6:8], "little") << 8) | len(r)
                i = np.searchsorted(keys, k)
                if i < len(keys) and keys[i] == k:
                    rows.append((k >> 24, (k >> 8) & 0xFFFF, len(r), float(tt), r[h + 1:-4].hex(), digest(r), gw_code[str(g)]))
        pd.DataFrame(rows, columns=list(OUT2_COLS)).astype(OUT2_COLS).to_parquet(p + ".tmp", index=False)
        os.replace(p + ".tmp", p)
        print("pass2", os.path.basename(name), len(rows), flush=True)


if __name__ == "__main__":
    z = zipfile.ZipFile(sys.argv[1]); what = sys.argv[2] if len(sys.argv) > 2 else "both"
    if what in ("pass1", "both"): pass1(z)
    if what in ("pass2", "both"): pass2(z)
    print("done", flush=True)
