"""E24: do the dataset authors' known-key test nodes appear in the evaluated Povalac and Kral captures? Reads only the first field of each line of the
dataset's key files (DevEUI in root_keys_lorawan, DevAddr in session_keys_lorawan, inside pcap.zip); key values are never read into output.
Also reports the first byte of the top reuse addresses in Brno. Counts only.
Usage: python -I src/scoping/e24_testdevices.py <pcap.zip>"""
import os, sys, zipfile
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_common as C

z = zipfile.ZipFile(sys.argv[1])
def first_fields(member):
    out = []
    for line in z.read(member).decode("ascii", "replace").splitlines():
        if line.startswith("#") or not line.strip(): continue
        out.append(line.split(",")[0].strip().strip('"').lower())
    return out
deveui = first_fields("root_keys_lorawan"); devaddr = first_fields("session_keys_lorawan")
print("test-node identifiers from the key files:", len(deveui), "DevEUI,", len(devaddr), "DevAddr:", deveui, devaddr)
want = {int(x, 16) for x in devaddr}
for city in ("liege", "graz", "brno", "wien"):
    fr = np.load(f"data/derived/povalac/{city}_frames.npz"); a = fr["addr"]
    J = pd.read_parquet(f"data/derived/povalac/{city}_joins.parquet")
    print(f"{city}: data-uplink receptions from the test DevAddrs {int(np.isin(a, list(want)).sum())} of {len(a)}; join requests from the test DevEUIs {int(J.deveui.isin(deveui).sum())}")
d = C.merge_receptions(pd.read_parquet("data/derived/povalac/brno_reuse.parquet"))
G = C.label_groups(C.analyse(d)); R = G[G.reuse]
fa = np.load("data/derived/povalac/brno_frames.npz")["addr"]
top = R.groupby("addr").frames.sum().sort_values(ascending=False).head(10)
print("Brno top-10 confirmed addresses: first byte of DevAddr (hex) and data-uplink receptions:", [(format(int(x) >> 24, "02x"), int((fa == x).sum())) for x in top.index])
print("done")
