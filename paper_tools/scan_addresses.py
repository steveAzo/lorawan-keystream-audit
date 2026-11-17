"""Privacy scan before release: does any file to be published contain a real device address (DevAddr) or DevEUI from the captures?
Builds the set of all DevAddrs (LoED pass-1 table and the four Povalac cities) and DevEUIs (join tables), then searches every given file for
each address as a decimal integer and as 8 hex digits (both byte orders, any case), and each DevEUI as 16 hex digits. Prints only file names
and counts of hits, never an address. Exit 1 if any file has a hit.
Usage (from the repository root): python -I paper_tools/scan_addresses.py <file or folder> ..."""
import glob, os, re, sys
import numpy as np, pandas as pd

addrs = set(np.unique(np.load("data/derived/loed_uplinks_v3.npz")["addr"]).tolist())
for c in ("liege", "graz", "brno", "wien"):
    addrs |= set(np.unique(np.load(f"data/derived/povalac/{c}_frames.npz")["addr"]).tolist())
euis = set()
for c in ("liege", "graz", "brno", "wien"):
    euis |= set(pd.read_parquet(f"data/derived/povalac/{c}_joins.parquet").deveui.str.lower())
J = pd.read_parquet("data/derived/join_requests.parquet")
col = [c for c in J.columns if "eui" in c.lower() and "join" not in c.lower()][0]
euis |= set(J[col].astype(str).str.lower().str.replace("0x", "", regex=False))
dec = {str(a) for a in addrs if a >= 100000}          # short integers would match ordinary counts
hexs = set()
for a in addrs:
    b = int(a).to_bytes(4, "little")
    hexs.add(b.hex()); hexs.add(b[::-1].hex())
print(f"addresses {len(addrs)} (decimal forms searched {len(dec)}), DevEUIs {len(euis)}")

files = []
for p in sys.argv[1:]:
    files += [f for f in glob.glob(os.path.join(p, "**", "*"), recursive=True) if os.path.isfile(f)] if os.path.isdir(p) else [p]
bad = 0
for f in sorted(files):
    if f.endswith((".png", ".pdf", ".npz", ".zip")): continue
    if f.endswith(".parquet"):
        try: txt = pd.read_parquet(f).to_csv(index=False)
        except Exception: txt = ""
    else:
        try: txt = open(f, encoding="utf-8", errors="ignore").read()
        except Exception: continue
    low = txt.lower()
    n_dec = sum(1 for tok in set(re.findall(r"(?<![\d.])\d{6,10}(?![\d.])", txt)) if tok in dec)
    n_hex = sum(1 for tok in set(re.findall(r"(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])", low)) if tok in hexs)
    n_eui = sum(1 for tok in set(re.findall(r"(?<![0-9a-f])[0-9a-f]{16}(?![0-9a-f])", low)) if tok in euis)
    if n_dec or n_hex or n_eui:
        bad += 1; print(f"HIT {f}: decimal {n_dec}, hex {n_hex}, DevEUI {n_eui}")
print(f"files scanned {len(files)}; files with hits {bad}")
sys.exit(1 if bad else 0)
