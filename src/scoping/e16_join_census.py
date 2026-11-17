"""E16: census of Join Requests in the full LoED capture (passive; join requests are sent in clear).
Join Request PHY: MHDR(1) JoinEUI(8) DevEUI(8) DevNonce(2) MIC(4) = 23 bytes, mtype 000. Per join request keeps time, SF, JoinEUI, DevEUI,
DevNonce; duplicate receptions (same DevEUI and DevNonce within 10 s) are merged. Output: data/derived/join_requests.parquet.
Usage: python -I src/scoping/e16_join_census.py <LoED_full.zip>"""
import base64, os, sys, zipfile
import numpy as np, pandas as pd
COLS = ["time", "physical_payload", "crc_status", "mtype", "spreading_factor", "bandwidth"]
z = zipfile.ZipFile(sys.argv[1]); out = []
for n in sorted(x for x in z.namelist() if x.endswith(".csv") and not x.startswith("__MACOSX")):
    with z.open(n) as fh:
        for c in pd.read_csv(fh, usecols=COLS, dtype=str, chunksize=200_000):
            c = c[(c.crc_status == "1") & (c.mtype == "000") & c.physical_payload.notna()]
            for tm, p, sf in zip(c.time, c.physical_payload, c.spreading_factor):
                r = base64.b64decode(p + "=" * (-len(p) % 4))
                if len(r) == 23:
                    out.append((tm, int(sf), r[1:9][::-1].hex(), r[9:17][::-1].hex(), int.from_bytes(r[17:19], "little")))
    print(os.path.basename(n), len(out), flush=True)
d = pd.DataFrame(out, columns=["time", "sf", "joineui", "deveui", "devnonce"])
d["t"] = (pd.to_datetime(d.time, utc=True, format="ISO8601") - pd.Timestamp("1970-01-01", tz="UTC")) / pd.Timedelta(seconds=1)
d = d.drop(columns="time").sort_values(["deveui", "devnonce", "t"])
same = (d.deveui == d.deveui.shift()) & (d.devnonce == d.devnonce.shift()) & ((d.t - d.t.shift()) < 10)
d = d[~same].sort_values(["deveui", "t"])
d.to_parquet("data/derived/join_requests.parquet", index=False)
print("join requests after merging duplicate receptions:", len(d), " DevEUIs:", d.deveui.nunique(), " JoinEUIs:", d.joineui.nunique())
