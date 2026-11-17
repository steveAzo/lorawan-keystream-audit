"""E25: mutation test of the ciphertext detector on the synthetic fleet of E20 (seed 20, capture probability 0.72). Runs the unmodified detector and three
mutants with the same random stream, and decides for each whether it is caught: caught if ciphertext false positives appear (m1, m2) or address-level recall
falls below half the baseline (m3). Writes results/e25_*.txt.
Usage: python -I src/scoping/e25_mutation_sim.py"""
import re, subprocess, sys
runs = {"baseline": [], "m1_direction_flipped": ["mut=m1"], "m2_threshold_lax": ["mut=m2"], "m3_offset_shifted": ["mut=m3"]}
res = {}
for name, extra in runs.items():
    out = subprocess.run([sys.executable, "-I", "src/scoping/e20_ground_truth_sim.py", "20", "0.72"] + extra, capture_output=True, text=True, check=True).stdout
    open(f"results/e25_mutation_{name}.txt", "w").write(out)
    fp = int(re.search(r"ciphertext   : .*\(false positives (\d+)\)", out).group(1))
    rec = float(re.search(r"ADDRESS-LEVEL at c=0.72: .*\(recall ([\d.]+)%\)", out).group(1))
    res[name] = (fp, rec); print(name, "false positives", fp, "address recall", rec, flush=True)
b_fp, b_rec = res["baseline"]
assert b_fp == 0, "baseline has false positives: the test of the mutants is void"
caught = {"m1_direction_flipped": res["m1_direction_flipped"][0] > 0, "m2_threshold_lax": res["m2_threshold_lax"][0] > 0,
          "m3_offset_shifted": res["m3_offset_shifted"][1] < b_rec / 2}
for k, v in caught.items(): print(k, "caught" if v else "NOT CAUGHT")
print(f"mutation: {sum(caught.values())} of {len(caught)} caught")
