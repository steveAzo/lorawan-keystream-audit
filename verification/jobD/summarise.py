"""Catch tables for the mutant runs (out/mut_povalac/*.txt and out/mut_loed/*.txt in this folder).
Povalac bed: the baseline must reproduce results/e23_povalac_audit.txt for the city, or this stops. Caught (narrow rule): confirmed addresses,
frames in confirmed triples or either placebo count differ from the baseline; "caught, wider rule" adds the counter-flagged addresses on
frames, examined triples and unresolved triples.
LoED bed: the baseline must reproduce the pipeline's numbers (e14, e15b, e18), or this stops. Caught: any decision number differs, or a
synthetic case is wrong. Usage (from the repository root): python -I <this folder>/summarise.py"""
import glob, os, re, sys

JD = os.path.dirname(os.path.abspath(__file__))
REF_P = {"wien": dict(conf=7, frames=1770, plac_f=0, ptot_f=371, plac_a=0, ptot_a=136239, flag=35, trip=1835, unres=3),
         "brno": dict(conf=58, frames=111115, plac_f=0, ptot_f=16296, plac_a=0, ptot_a=225924, flag=78, trip=20723, unres=48)}
# references: results/e23_povalac_audit.txt (uplink concentrator)
REF_L = dict(frames=883887, xgw=1190, flag=1222, ftrip=190847, exam=187884, ctrip=45207, conf=236, cframes=193053, unres=36,
             ishort=35996, plac=0, ptot=24001, gb_n=229, gb_r=203, gb_res=1007, gb_drop=1145, gb_wrap=0, syn_bad=0)


def g(p, s, d=None):
    m = re.search(p, s); return int(m.group(1)) if m else d


def parse_p(txt):
    res = {}
    for blk in re.split(r"\n===== ", txt)[1:]:
        city = blk.split(":", 1)[0].strip()
        res[city] = dict(flag=g(r"on frames with the gateway-aware merge \(main\): triples \d+, addresses (\d+)", blk),
                         trip=g(r"examined \(a testable pair\) (\d+)", blk), conf=g(r"\nconfirmed addresses (\d+) =", blk),
                         frames=g(r"frames in confirmed triples (\d+)", blk, 0),
                         plac_f=g(r"placebo on frames of flagged triples .*?: (\d+) related", blk), ptot_f=g(r"placebo on frames of flagged triples .*? related of (\d+) pairs", blk),
                         plac_a=g(r"placebo on all frames .*?: (\d+) related", blk), ptot_a=g(r"placebo on all frames .*? related of (\d+) pairs", blk),
                         unres=g(r"unresolved \(only identical pairs < \d+ h apart\) (\d+)", blk))
    return res


def parse_l(s):
    return dict(frames=g(r"\nframes (\d+);", s),
                xgw=g(r"copies merged across gateways (\d+)", s), flag=g(r"counter-flagged addresses (\d+)", s),
                ftrip=g(r"flagged triples with FRMPayload (\d+)", s), exam=g(r"; examined (\d+);", s), ctrip=g(r"confirmed triples (\d+);", s),
                conf=g(r"confirmed addresses (\d+);", s), cframes=g(r"frames in confirmed triples (\d+)", s), unres=g(r"unresolved addresses (\d+)", s),
                ishort=g(r"identical-short pairs (\d+)", s), plac=g(r"placebo within address buckets: (\d+) related", s), ptot=g(r"related of (\d+) pairs", s),
                gb_n=g(r"addresses with >= 20 frames (\d+)", s), gb_r=g(r"with a reset (\d+)", s), gb_res=g(r"; resets (\d+);", s),
                gb_drop=g(r"; drops (\d+);", s), gb_wrap=g(r"; wraps (\d+)", s), syn_bad=g(r"synthetic cases wrong: (\d+)", s))


print("== Povalac bed")
runs = {}
for p in sorted(glob.glob(os.path.join(JD, "out", "mut_povalac", "*.txt"))):
    runs.setdefault(os.path.basename(p)[:-4].split("__")[0], {}).update(parse_p(open(p, encoding="utf-8").read()))
base = runs.get("baseline", {})
for city, ref in REF_P.items():
    if city in base:
        bad = {k: (base[city][k], v) for k, v in ref.items() if base[city][k] != v}
        if bad: sys.exit(f"Povalac baseline {city} does not reproduce results/e23_povalac_audit.txt: {bad}")
        print(f"baseline reproduces results/e23_povalac_audit.txt on {city}")
print("mutant | city | flagged addr (frames) | examined triples | unresolved triples | confirmed addr | frames in confirmed | placebo flagged | placebo all | caught | caught, wider rule")
cp, cw = {}, {}
for name, r in runs.items():
    if name == "baseline": continue
    for city in sorted(r):
        x, b = r[city], base.get(city)
        if b is None: continue
        c = any(x[k] != b[k] for k in ("conf", "frames", "plac_f", "plac_a"))
        w = c or any(x[k] != b[k] for k in ("flag", "trip", "unres"))
        cp[name] = cp.get(name, False) or c; cw[name] = cw.get(name, False) or w
        print(f"{name} | {city} | {x['flag']} | {x['trip']} | {x['unres']} | {x['conf']} | {x['frames']} | {x['plac_f']}/{x['ptot_f']} | {x['plac_a']}/{x['ptot_a']} | {'yes' if c else 'no'} | {'yes' if w else 'no'}")
for city in sorted(base):
    b = base[city]; print(f"baseline | {city} | {b['flag']} | {b['trip']} | {b['unres']} | {b['conf']} | {b['frames']} | {b['plac_f']}/{b['ptot_f']} | {b['plac_a']}/{b['ptot_a']} | - | -")
print(f"Povalac bed: caught {sum(cp.values())} of {len(cp)} (narrow rule); {sum(cw.values())} of {len(cw)} (wider rule); not caught (wider rule): {', '.join(k for k, v in cw.items() if not v) or 'none'}")

print("\n== LoED bed")
L = {os.path.basename(p)[:-4]: parse_l(open(p, encoding="utf-8").read()) for p in sorted(glob.glob(os.path.join(JD, "out", "mut_loed", "*.txt")))}
if "baseline" in L:
    bad = {k: (L["baseline"][k], v) for k, v in REF_L.items() if L["baseline"][k] != v}
    if bad: sys.exit(f"LoED baseline does not reproduce the pipeline: {bad}")
    print("baseline reproduces e14, e15b and e18 (frames, merged copies, flagged, confirmed, unresolved, Gate B)")
keys = list(REF_L)
print("mutant | " + " | ".join(keys) + " | caught | what moved")
cl = {}
for name, x in L.items():
    if name == "baseline": continue
    moved = [k for k in keys if x[k] != REF_L[k]]
    cl[name] = bool(moved)
    print(f"{name} | " + " | ".join(str(x[k]) for k in keys) + f" | {'yes' if moved else 'no'} | {', '.join(moved)}")
print(f"LoED bed: caught {sum(cl.values())} of {len(cl)}; not caught: {', '.join(k for k, v in cl.items() if not v) or 'none'}")
