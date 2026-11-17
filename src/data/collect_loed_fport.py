"""Collect the FPort of the LoED receptions that pass 2 of collect_loed.py keeps (triples with receptions >= COLLECT_GAP s apart), so the
audit can report how many triples mix ports (port 0 is encrypted with NwkSKey, other ports with AppSKey). The stored FRMPayload starts after
the port byte, so the port must be read again from the raw zip. Output: data/derived/loed_fport_v3.parquet with one row per distinct PHY
payload digest (columns phy, fport); the digest is the one stored in reuse_frames_v3, so the port joins to every reception. Only the port
byte is read; no payload is decoded or printed.
Usage: python -I src/data/collect_loed_fport.py <LoED_full.zip>; run from the repository root."""
import os, sys, zipfile
from array import array
import numpy as np, pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scoping"))
from collect_loed import chunks, frame, digest, day_files
from audit_common import counter_test, COLLECT_GAP, LOED_UPLINKS

OUT = "data/derived/loed_fport_v3.parquet"

u = np.load(LOED_UPLINKS)
m = u["body"] == 1
a, f, s, t = u["addr"][m], u["fcnt"][m].astype(np.int64), u["size"][m].astype(np.int64), u["t"][m]
fa, ff, fs, *_ = counter_test(a, f, s, t, min_gap=COLLECT_GAP)
keys = np.unique((fa << 24) | (ff << 8) | fs); del a, f, s, t, u, m
print("triples:", len(keys), flush=True)
H, P = array("q"), array("h")
z = zipfile.ZipFile(sys.argv[1])
for di, name in enumerate(day_files(z)):
    for c, tt in chunks(z, name):
        for pl in c.physical_payload:
            r = frame(pl)
            if r is None: continue
            h = 8 + (r[5] & 0x0F)
            if len(r) <= h + 5: continue
            k = (int.from_bytes(r[1:5], "little") << 24) | (int.from_bytes(r[6:8], "little") << 8) | len(r)
            i = np.searchsorted(keys, k)
            if i < len(keys) and keys[i] == k:
                H.append(digest(r)); P.append(r[h])
    if di % 10 == 0:
        print("day", di, os.path.basename(name), len(H), flush=True)
        if len(H) > 2_000_000:   # keep memory flat: reduce to distinct digests
            x = pd.DataFrame({"phy": np.frombuffer(H, np.int64), "fport": np.frombuffer(P, np.int16)}).drop_duplicates("phy")
            H, P = array("q", x.phy.to_numpy().tobytes()), array("h", x.fport.to_numpy().astype(np.int16).tobytes())
x = pd.DataFrame({"phy": np.frombuffer(H, np.int64), "fport": np.frombuffer(P, np.int16)}).drop_duplicates("phy")
x.to_parquet(OUT, index=False)
print("distinct PHY payloads:", len(x), "done", flush=True)
