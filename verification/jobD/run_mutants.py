"""Mutation test of the real-data pipeline. Each mutant is a textual change applied to a fresh copy of audit_common.py, parse_povalac.py and
e23_povalac_audit.py under work/<mutant>/ in this folder; a patch that does not match exactly once stops the run.
Beds:
  povalac  parse (only when the mutant touches parse_povalac.py; otherwise the baseline parse is reused) and e23 on the named captures
  loed     loed_bed.py (this folder) with the mutated audit_common.py on the collected LoED files (no re-collection; valid for
           mutants of audit_common.py only)
Counts only. Derived copies of the Povalac traffic are deleted at the end of each run.
Usage (from the repository root): python -I <this folder>/run_mutants.py <povalac|loed> <mutant|all|list> [city_log ...]"""
import hashlib, os, shutil, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
JD = os.path.dirname(os.path.abspath(__file__))
ZIP = os.path.join(ROOT, "data", "raw", "povalac_lorawan", "log.zip")
FILES = ["src/scoping/audit_common.py", "src/data/parse_povalac.py", "src/scoping/e23_povalac_audit.py"]
AC, PP = FILES[0], FILES[1]

MUTANTS = {
    "baseline": [],
    # detector, parser and frame rules
    # a: the shared relatedness rule; a2: classify()'s call to it
    "a_sign_reversed": [(AC, "    return k <= kstar(4 * len(x), thr)", "    return k > kstar(4 * len(x), thr)")],
    "a2_sign_reversed_classify_call": [(AC, "        if related(bd[i][:L], bd[j][:L], thr, k): rel += 1", "        if not related(bd[i][:L], bd[j][:L], thr, k): rel += 1")],
    "b1_offset_minus1": [(PP, "r[h + 1:-4].hex()", "r[h:-4].hex()")],
    "b2_fopts_ignored": [(PP, "h = 8 + (r[5] & 0x0F)", "h = 8")],
    "c_no_min_gap": [(AC, "MIN_GAP = 600", "MIN_GAP = 0")],
    "d_no_equal_length": [(AC, "            if len(x) != len(y):\n                if not prefix:", "            if False:\n                if not prefix:")],
    "e_thresh_0.3": [(AC, "THRESH = 1e-6", "THRESH = 0.3")],
    "f_no_size_in_key": [(PP, "S.append(len(r)); T.append(t)", "S.append(0); T.append(t)"),
                         (PP, 'int.from_bytes(r[6:8], "little"), len(r), t_,', 'int.from_bytes(r[6:8], "little"), 0, t_,')],
    "g_dup_win_0": [(AC, "DUP_WIN = 60\n", "DUP_WIN = 0\n")],
    # h breaks the identical-gap comparison (setting IDENT_GAP = 0 would stop at the import assert XGW_WIN <= IDENT_GAP)
    "h_ident_gap_0": [(AC, "            if gap >= ident_gap: ide += 1", "            if gap >= 0: ide += 1")],
    # new: the gateway-aware frame rule
    "x1_gw_disjointness_ignored": [(AC, "if (mh & gi) == 0 and tf[i] - tf[h] < xgw_win:", "if tf[i] - tf[h] < xgw_win:")],
    "x2_no_time_window": [(AC, "if (mh & gi) == 0 and tf[i] - tf[h] < xgw_win:", "if (mh & gi) == 0:")],
    "x3_disjointness_inverted": [(AC, "if (mh & gi) == 0 and tf[i] - tf[h] < xgw_win:", "if (mh & gi) != 0 and tf[i] - tf[h] < xgw_win:")],
    "x4_mask_not_accumulated": [(AC, "hd[i] = h; ml[h] = mh | gi", "hd[i] = h; ml[h] = mh")],
    "x5_window_from_previous_frame": [(AC, "if (mh & gi) == 0 and tf[i] - tf[h] < xgw_win:", "if (mh & gi) == 0 and tf[i] - tf[i - 1] < xgw_win:")],
    "x6_payload_not_in_frame_key": [(AC, 'd["size"].to_numpy()), tid], d.t.to_numpy()', 'd["size"].to_numpy())], d.t.to_numpy()'),
                                    (AC, 'frame_index([triple_key(a, f, s), g("phy")], t,', 'frame_index([triple_key(a, f, s)], t,')],
    "x7_window_24h": [(AC, "XGW_WIN = 6 * 3600", "XGW_WIN = 24 * 3600")],
    "x8_rule_off": [(AC, "XGW_WIN = 6 * 3600", "XGW_WIN = 0")],
    # new: the counter-reset rule (Gate B); scored on the LoED bed
    "r1_no_continuation": [(AC, "return int((drop & ~wrap & cont).sum())", "return int((drop & ~wrap).sum())")],
    "r2_wraps_counted": [(AC, "return int((drop & ~wrap & cont).sum())", "return int((drop & cont).sum())")],
    "r3_any_drop": [(AC, "d = np.diff(f); drop = d < -step_max", "d = np.diff(f); drop = d < 0")],
    "r4_last_drop_counted": [(AC, "nxt = np.r_[d[1:], -1]", "nxt = np.r_[d[1:], 0]")],
    "r5_wrap_test_wrong": [(AC, "wrap = drop & (f[:-1] >= 65536 - wrap_tol) & (f[1:] < wrap_tol)", "wrap = drop & (f[:-1] >= 65536 - wrap_tol)")],
    "r6_continuation_too_wide": [(AC, "cont = (nxt >= 0) & (nxt <= step_max)", "cont = (nxt >= -65536)")],
}
TOUCH_PARSE = {k for k, v in MUTANTS.items() if any(f == PP for f, _, _ in v)}


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def build(name):
    w = os.path.join(JD, "work", name)
    if os.path.isdir(w): shutil.rmtree(w)
    for f in FILES:
        os.makedirs(os.path.dirname(os.path.join(w, f)), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, f), os.path.join(w, f))
    for f, old, new in MUTANTS[name]:
        p = os.path.join(w, f); s = open(p, encoding="utf-8").read()
        n = s.count(old)
        if n != 1:
            raise SystemExit(f"{name}: patch matched {n} times in {f}: {old!r}")
        open(p, "w", encoding="utf-8").write(s.replace(old, new))
    return w


def header(name, w):
    return [f"mutant {name}", "source hashes (sha256, 16 hex): " + ", ".join(f"{f} {sha(os.path.join(w, f))}" for f in FILES),
            "originals: " + ", ".join(f"{f} {sha(os.path.join(ROOT, f))}" for f in FILES), "patches: " + repr(MUTANTS[name])]


def run_povalac(name, logs):
    w = build(name); t0 = time.time()
    cities = [x.split(".")[0].split("_", 1)[1].lower() for x in logs]
    base_data = os.path.join(JD, "work", "_parsed_" + "_".join(cities))
    txt = "\n".join(header(name, w)) + "\n"
    if name in TOUCH_PARSE or not os.path.isdir(base_data):
        p1 = subprocess.run([sys.executable, "-I", "src/data/parse_povalac.py", ZIP, *logs], cwd=w, capture_output=True, text=True)
        txt += "--- parse (exit %d)\n" % p1.returncode + p1.stdout + p1.stderr[-3000:]
        ok = p1.returncode == 0
        if ok and name == "baseline":
            shutil.copytree(os.path.join(w, "data"), base_data)
    else:
        shutil.copytree(base_data, os.path.join(w, "data")); txt += "--- parse: baseline parse reused (mutant does not touch parse_povalac.py)\n"; ok = True
    if ok:
        p2 = subprocess.run([sys.executable, "-I", "src/scoping/e23_povalac_audit.py", *cities], cwd=w, capture_output=True, text=True)
        txt += "--- audit (exit %d)\n" % p2.returncode + p2.stdout + p2.stderr[-3000:]
    txt += f"--- seconds {time.time() - t0:.0f}\n"
    os.makedirs(os.path.join(JD, "out", "mut_povalac"), exist_ok=True)
    open(os.path.join(JD, "out", "mut_povalac", f"{name}__{'_'.join(cities)}.txt"), "w", encoding="utf-8").write(txt)
    shutil.rmtree(os.path.join(w, "data"), ignore_errors=True)
    print(name, "povalac", cities, f"{time.time() - t0:.0f} s", flush=True)


def run_loed(name):
    if name in TOUCH_PARSE: print(name, "touches parse_povalac.py only; not a LoED-bed mutant"); return
    w = build(name); t0 = time.time()
    p = subprocess.run([sys.executable, "-I", os.path.join(JD, "loed_bed.py"), os.path.join(w, "src", "scoping")], cwd=ROOT, capture_output=True, text=True)
    txt = "\n".join(header(name, w)) + "\n--- loed bed (exit %d)\n" % p.returncode + p.stdout + p.stderr[-3000:] + f"--- seconds {time.time() - t0:.0f}\n"
    os.makedirs(os.path.join(JD, "out", "mut_loed"), exist_ok=True)
    open(os.path.join(JD, "out", "mut_loed", f"{name}.txt"), "w", encoding="utf-8").write(txt)
    print(name, "loed", p.returncode, f"{time.time() - t0:.0f} s", flush=True)


if __name__ == "__main__":
    bed, which = sys.argv[1], sys.argv[2]; logs = sys.argv[3:] or ["05_Wien.log"]
    names = list(MUTANTS) if which == "all" else which.split(",")
    for m in names:
        run_povalac(m, logs) if bed == "povalac" else run_loed(m)
    if bed == "povalac":
        shutil.rmtree(os.path.join(JD, "work", "_parsed_" + "_".join(x.split(".")[0].split("_", 1)[1].lower() for x in logs)), ignore_errors=True)
    print("done", flush=True)
