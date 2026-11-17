"""E27b: confirmed LoED addresses in total when the triples above the 80-frame cap are tested on all their frames, or on 80 frames spread
evenly, instead of their first 80 (all other triples as in the main rule). Reads results/e27_triples.parquet. Usage: python -I src/scoping/e27b_cap_totals.py"""
import pandas as pd

T = pd.read_parquet("results/e27_triples.parquet"); cap = T.frames > 80; main = set(T[T.confirmed].addr)
for lab, s in (("all frames", "all"), ("80 frames spread evenly", "even")):
    c = T.confirmed.to_numpy().copy()
    c[cap.to_numpy()] = ((T[f"minlp_{s}"] < -6) | (T[f"maxident_{s}"] >= 6 * 3600))[cap].to_numpy()
    a = set(T[c].addr)
    print(f"capped triples tested on {lab}: confirmed addresses {len(a)}; added {len(a - main)}, lost {len(main - a)}")
print("done")
