"""Build the manuscript figures (draft/figs/*.pdf, vector, and *.png at 600 dpi for the Word copy) from the result files only.
Style: Times New Roman to match the text; categorical colours are the first three slots of the validated reference palette
(blue #2a78d6, orange #eb6834, aqua #1baf7a; all-pairs CVD and normal-vision checks pass), always with a second cue (marker or line style)
and direct labels, since aqua is below 3:1 contrast on white; recessive grey axes and grid; one y-axis per chart.
Numbers drawn in the diagrams are read from results/ by pattern, never typed.
Usage (from the repository root): python -I paper_tools/make_figs.py"""
import math, os, re, sys
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

sys.path.insert(0, "src/scoping")
import audit_common as C

OUT = "draft/figs"; os.makedirs(OUT, exist_ok=True)
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED, GRID, FILL = "#0b0b0b", "#52514e", "#8a8984", "#e6e5e0", "#f3f2ee"
W = 5.4   # text width of the elsarticle preprint in inches (388.6 pt)
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "STIXGeneral"], "mathtext.fontset": "stix",
    "font.size": 9, "axes.labelsize": 9, "xtick.labelsize": 8, "ytick.labelsize": 8, "legend.fontsize": 8,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2, "axes.linewidth": 0.6,
    "xtick.major.width": 0.6, "ytick.major.width": 0.6, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.axisbelow": True, "lines.linewidth": 1.4,
    "legend.frameon": False, "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02})


def res(f):
    return open(f"results/{f}", encoding="utf-8").read()


def num(f, pat):
    m = re.search(pat, res(f)); assert m, (f, pat); return int(m.group(1))


def save(fig, name):
    fig.savefig(f"{OUT}/{name}.pdf"); fig.savefig(f"{OUT}/{name}.png", dpi=600); plt.close(fig); print("wrote", name)


def box(ax, x, y, w, h, text, fc="white", ec=MUTED, size=8.5, weight="normal", color=INK, lw=0.8, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.06", fc=fc, ec=ec, lw=lw, ls=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, color=color, weight=weight, linespacing=1.25)


def arrow(ax, x0, y0, x1, y1, color=INK2, ls="-"):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=9, lw=0.8, color=color, ls=ls, shrinkA=0, shrinkB=0))


# ------------------------------------------------------------------ diagrams: TikZ (text wraps inside nodes; the manuscript's Times)
TIKZ_HEAD = r"""\documentclass[border=3pt]{standalone}
\usepackage{mathptmx}
\usepackage{tikz}
\usetikzlibrary{positioning,arrows.meta,fit,calc,decorations.pathreplacing,backgrounds}
\definecolor{cblue}{HTML}{2A78D6}\definecolor{corange}{HTML}{EB6834}\definecolor{caqua}{HTML}{1BAF7A}
\definecolor{ink}{HTML}{0B0B0B}\definecolor{ink2}{HTML}{52514E}\definecolor{muted}{HTML}{8A8984}\definecolor{fillg}{HTML}{F3F2EE}
\definecolor{fblue}{HTML}{DBE8F8}\definecolor{forange}{HTML}{FDE3D8}
\begin{document}
\hyphenpenalty=10000 \exhyphenpenalty=10000 \frenchspacing
"""


def tikz(name, body):
    import subprocess
    src = f"{OUT}/{name}.tex"
    open(src, "w", encoding="utf-8").write(TIKZ_HEAD + body + "\n\\end{document}\n")
    r = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", f"-output-directory={OUT}", src], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{name}: pdflatex failed\n" + r.stdout[-2500:])
    subprocess.run(["pdftoppm", "-r", "600", "-png", "-singlefile", f"{OUT}/{name}.pdf", f"{OUT}/{name}"], check=True)
    for ext in ("aux", "log"):
        if os.path.exists(f"{OUT}/{name}.{ext}"): os.remove(f"{OUT}/{name}.{ext}")
    print("wrote", name, "(TikZ)")


def fig_encryption():
    body = r"""\begin{tikzpicture}[font=\small, >={Latex[length=2mm]},
  fld/.style={draw=muted, fill=fillg, minimum height=7mm, inner sep=1pt, outer sep=0pt},
  blk/.style={draw=ink2, rounded corners=1.5pt, align=center, minimum height=10mm, inner sep=3pt},
  sz/.style={font=\footnotesize, text=ink2},
  note/.style={font=\footnotesize, text=ink2, align=left}]
% ---- the frame
\node[fld, minimum width=11mm] (mhdr) at (0,0) {MHDR};
\node[fld, minimum width=18mm, right=0mm of mhdr] (addr) {DevAddr};
\node[fld, minimum width=11mm, right=0mm of addr] (fctrl) {FCtrl};
\node[fld, minimum width=12mm, right=0mm of fctrl] (fcnt) {FCnt};
\node[fld, minimum width=13mm, right=0mm of fcnt] (fopts) {FOpts};
\node[fld, minimum width=11mm, right=0mm of fopts] (fport) {FPort};
\node[fld, draw=cblue, fill=fblue, minimum width=40mm, right=0mm of fport] (pay) {FRMPayload (encrypted)};
\node[fld, draw=corange, fill=forange, minimum width=12mm, right=0mm of pay] (mic) {MIC};
\foreach \n/\t in {mhdr/1, addr/4, fctrl/1, fcnt/2, fopts/0--15, fport/1, pay/$n$, mic/4}
  \node[sz, below=0.4mm of \n] {\t\ B};
\draw[decorate, decoration={brace, amplitude=3pt, raise=1pt}, draw=corange] (mhdr.north west) -- (pay.north east)
  node[midway, above=4pt, note] {covered by the MIC: AES-CMAC with the network session key over $B_0$ and these bytes};
\node[font=\small\bfseries, anchor=south west] at ($(mhdr.north west)+(0,6.5mm)$) {LoRaWAN 1.0.x data uplink};
% ---- keystream row (y = 0 of this part), with the two frames above and below the keystream block
\coordinate (o) at ($(mhdr.south west)+(66mm,-34mm)$);
\node[blk, draw=cblue, fill=fblue, minimum width=17mm] (ks) at (o) {keystream\\ block $S_i$};
\node[blk, left=6mm of ks, minimum width=20mm] (aes) {AES-128\\ session key $K$};
\node[blk, fill=fillg, left=6mm of aes, text width=31mm] (ai)
  {block $A_i$: 0x01 $|$ 0x00${\times}$4 $|$ direction $|$ DevAddr $|$ FCnt (32 bit) $|$ 0x00 $|$ $i$};
\draw[->, ink2] (ai) -- (aes); \draw[->, ink2] (aes) -- (ks);
\draw[->, muted, dashed] ($(addr.south)+(0,-3.5mm)$) -- ($(ai.north west)!0.35!(ai.north east)$);
\draw[->, muted, dashed] ($(fcnt.south)+(0,-3.5mm)$) -- ($(ai.north west)!0.75!(ai.north east)$);
\node[note, below=2mm of ai, text width=34mm] {The keystream depends on $K$, the direction, DevAddr, the 32-bit counter and $i$ only, not on the payload or its length.};
\node[circle, draw=ink, inner sep=0pt, minimum size=5mm, font=\normalsize] (x1) at ($(ks)+(0,15mm)$) {$\oplus$};
\node[circle, draw=ink, inner sep=0pt, minimum size=5mm, font=\normalsize] (x2) at ($(ks)+(0,-15mm)$) {$\oplus$};
\node[blk, draw=cblue, left=6mm of x1, minimum width=20mm] (p1) {plaintext $P_1$};
\node[blk, draw=corange, left=6mm of x2, minimum width=20mm] (p2) {plaintext $P_2$};
\node[blk, draw=cblue, right=6mm of x1, minimum width=20mm] (c1) {ciphertext $C_1$};
\node[blk, draw=corange, right=6mm of x2, minimum width=20mm] (c2) {ciphertext $C_2$};
\draw[->] (p1) -- (x1); \draw[->] (x1) -- (c1); \draw[->] (p2) -- (x2); \draw[->] (x2) -- (c2);
\draw[->, cblue, thick] (ks.north) -- (x1.south); \draw[->, cblue, thick] (ks.south) -- (x2.north);
\node[note, text=cblue, right=1.5mm of ks, text width=19mm] {same DevAddr, FCnt and $K$: one keystream, used twice};
\node[blk, fill=fillg, anchor=west, text width=34mm, align=left] (eq) at ($(ks.east)+(31mm,0)$)
  {$C_1 \oplus C_2 = P_1 \oplus P_2$\\[2pt]{\footnotesize zero wherever the two plaintexts agree, so few bits differ and the pair is related; under independent keystreams about half of the bits differ}};
\draw[->, ink2] (c1.east) -- (eq.north west); \draw[->, ink2] (c2.east) -- (eq.south west);
\end{tikzpicture}"""
    tikz("fig_encryption", body)


def fig_encryption_mpl():
    fig, ax = plt.subplots(figsize=(W, 3.05)); ax.set_xlim(0, 10); ax.set_ylim(0, 6.1); ax.axis("off")
    fields = [("MHDR", 1, "1"), ("DevAddr", 4, "4"), ("FCtrl", 1, "1"), ("FCnt", 2, "2"), ("FOpts", 2.2, "0–15"), ("FPort", 1, "1"),
              ("FRMPayload", 5.2, "n"), ("MIC", 4, "4")]
    total = sum(w for _, w, _ in fields); x = 0.25; scale = 9.5 / total; y = 5.0
    pos = {}
    for name, w, nb in fields:
        ww = w * scale
        fc = "#dbe8f8" if name == "FRMPayload" else ("#fde3d8" if name == "MIC" else FILL)
        ec = BLUE if name == "FRMPayload" else (ORANGE if name == "MIC" else MUTED)
        ax.add_patch(Rectangle((x, y), ww, 0.55, fc=fc, ec=ec, lw=0.8))
        ax.text(x + ww / 2, y + 0.275, name, ha="center", va="center", fontsize=8)
        ax.text(x + ww / 2, y - 0.17, nb + " B", ha="center", va="center", fontsize=7, color=INK2)
        pos[name] = (x, ww); x += ww
    ax.text(0.25, 5.85, "LoRaWAN 1.0.x data uplink (PHY payload)", fontsize=8.5, color=INK, weight="bold")
    fx, fw = pos["FRMPayload"]
    ax.annotate("", xy=(pos["MHDR"][0], 5.68), xytext=(fx + fw, 5.68), arrowprops=dict(arrowstyle="<->", lw=0.6, color=ORANGE))
    ax.text((pos["MHDR"][0] + fx + fw) / 2 + 1.6, 5.68, "MIC = AES-CMAC(NwkSKey, B$_0$ | MHDR … FRMPayload)[0:4]", fontsize=7, color=INK2,
            ha="center", va="bottom")
    # keystream generation
    yk = 3.25
    box(ax, 0.25, yk, 3.55, 0.75, "$A_i$ = 0x01 | 0x00$\\times$4 | Dir | DevAddr |\nFCnt (32 bit) | 0x00 | $i$", fc=FILL, size=7.8)
    box(ax, 4.25, yk, 1.35, 0.75, "AES-128\nkey $K$", fc="white", ec=INK2, size=8)
    box(ax, 6.05, yk, 1.15, 0.75, "keystream\n$S_i$", fc="#dbe8f8", ec=BLUE, size=8)
    arrow(ax, 3.8, yk + 0.375, 4.25, yk + 0.375); arrow(ax, 5.6, yk + 0.375, 6.05, yk + 0.375)
    ax.add_patch(FancyArrowPatch((pos["DevAddr"][0] + pos["DevAddr"][1] / 2, y - 0.3), (1.6, yk + 0.78), arrowstyle="-|>",
                                 mutation_scale=8, lw=0.6, color=MUTED, ls=(0, (2, 2))))
    ax.add_patch(FancyArrowPatch((pos["FCnt"][0] + pos["FCnt"][1] / 2, y - 0.3), (2.6, yk + 0.78), arrowstyle="-|>",
                                 mutation_scale=8, lw=0.6, color=MUTED, ls=(0, (2, 2))))
    ax.text(0.25, 4.25, "The keystream depends on $K$, direction, DevAddr, the 32-bit counter and $i$ only, not on the payload.",
            fontsize=7.5, color=INK2)
    # two frames with one counter
    y1, y2 = 1.65, 0.45
    for yy, sub, col in ((y1, "1", BLUE), (y2, "2", ORANGE)):
        box(ax, 0.25, yy, 1.55, 0.6, f"plaintext $P_{sub}$", fc="white", ec=col, size=8)
        ax.text(2.2, yy + 0.3, "$\\oplus$", fontsize=13, ha="center", va="center", color=INK)
        box(ax, 2.6, yy, 1.55, 0.6, f"ciphertext $C_{sub}$", fc="white", ec=col, size=8)
        arrow(ax, 1.8, yy + 0.3, 2.05, yy + 0.3); arrow(ax, 2.35, yy + 0.3, 2.6, yy + 0.3)
    ax.plot([6.62, 6.62], [yk, 1.25], color=BLUE, lw=0.8); ax.plot([2.2, 6.62], [1.25, 1.25], color=BLUE, lw=0.8)
    arrow(ax, 2.2, 1.25, 2.2, y1 + 0.13, color=BLUE); arrow(ax, 2.2, 1.25, 2.2, y2 + 0.47, color=BLUE)
    ax.text(4.35, 1.33, "same DevAddr and FCnt, same $K$:\nthe same keystream twice", fontsize=7.5, color=INK2, va="bottom")
    box(ax, 6.0, 0.45, 3.75, 1.8, "$C_1 \\oplus C_2 = P_1 \\oplus P_2$\n\nzero wherever the plaintexts agree:\nfew differing bits, so the pair is\nrelated; independent keystreams give\nabout half the bits different",
        fc=FILL, ec=INK2, size=8)
    arrow(ax, 4.15, y1 + 0.3, 6.0, 1.55); arrow(ax, 4.15, y2 + 0.3, 6.0, 1.0)
    save(fig, "fig_encryption")


# ------------------------------------------------------------------ Fig. 2: the audit pipeline with the LoED counts (TikZ)
def fig_pipeline():
    g = lambda f_, p: f"{num(f_, p):,}"
    E14, E15 = "e14_counter_reuse_census.txt", "e15b_reuse_analysis.txt"
    v = dict(REC=g(E14, r"data-uplink receptions (\d+)"), FR=g(E14, r"\(main\): (\d+) \("), CP=g(E14, r"absorbed (\d+) copies"),
             FT=g(E14, r"with the gateway-aware merge \(main\): triples (\d+), addresses"),
             FA=g(E14, r"with the gateway-aware merge \(main\): triples \d+, addresses (\d+)"),
             EX=g(E15, r"examined \(a testable pair\): (\d+)"), CT=g(E15, r"triples with related or identical pairs: (\d+)"),
             CA=g(E15, r"confirmed addresses: (\d+)"), UR=g(E15, r"with only unrelated pairs: (\d+)"),
             US=g(E15, r"unresolved triples \(only identical pairs under 6 h\): (\d+)"), UA=g(E15, r"no examined triple: (\d+)"))
    body = r"""\begin{tikzpicture}[font=\small, >={Latex[length=2mm]}, node distance=5mm,
  st/.style={draw=muted, fill=fillg, rounded corners=1.5pt, align=center, text width=78mm, inner sep=3pt, minimum height=11mm},
  res/.style={draw=muted, rounded corners=1.5pt, align=center, text width=24mm, inner sep=3pt, minimum height=19mm},
  side/.style={rounded corners=1.5pt, dashed, align=left, text width=46mm, inner sep=3pt, font=\footnotesize},
  num/.style={font=\small\bfseries}]
\node[st] (rec) {Receptions: CRC-valid data uplinks, one row per gateway\\ {\bfseries @REC@}};
\node[st, below=of rec] (frm) {Frames: same PHY payload, each reception within 60\,s of the previous one; a copy heard only by new gateways within 6\,h is merged (@CP@ copies)\\ {\bfseries @FR@ frames}};
\node[st, fill=white, draw=ink2, below=of frm] (ctr) {Counter test: a (DevAddr, FCnt, size) triple with two frames at least 10\,min apart\\ {\bfseries @FT@ triples on @FA@ addresses}};
\node[st, fill=fblue, draw=cblue, below=of ctr] (cip) {Ciphertext test on each pair of equal FRMPayload length:\\ related if \mbox{$\Pr[\mathrm{Bin}(8n,\frac12)\le k] < 10^{-6}$},\\ or identical at least 6\,h apart\\ {\bfseries @EX@ triples with a testable pair}};
\draw[->, ink2] (rec) -- (frm); \draw[->, ink2] (frm) -- (ctr); \draw[->, ink2] (ctr) -- (cip);
\node[res, draw=cblue, line width=0.9pt, below=9mm of cip.south west, anchor=north west] (o1) {{\bfseries Confirmed}\\ @CT@ triples\\ {\bfseries @CA@ addresses}};
\node[res, below=9mm of cip.south, anchor=north] (o2) {Only unrelated\\ pairs\\ @UR@ triples};
\node[res, below=9mm of cip.south east, anchor=north east] (o3) {Unresolved: only identical, under 6\,h\\ @US@ triples\\ @UA@ further addresses};
\foreach \o in {o1,o2,o3} \draw[->, ink2] (cip.south) -- (\o.north);
\node[side, draw=corange, right=6mm of frm.north east, anchor=north west] (ctl) {{\bfseries Controls}: pairs that cannot share a keystream\\[1pt]
  $\bullet$ different addresses, same FCnt and size\\ $\bullet$ one address, different counters\\ $\bullet$ one address, adjacent counters\\[1pt] 0 related pairs in every control};
\node[side, draw=caqua, right=6mm of cip.north east, anchor=north west] (val) {{\bfseries Validation}: reuse that must be found\\[1pt]
  $\bullet$ detection power by payload length\\ $\bullet$ synthetic fleet with known truth\\ $\bullet$ Brno devices whose MICs verify under a published default key\\ $\bullet$ mutation test of the pipeline};
\draw[->, corange, dashed] (ctl.south west) -- (cip.north east);
\draw[->, caqua, dashed] (val.west) -- (cip.east);
\end{tikzpicture}"""
    for k, val in v.items(): body = body.replace("@" + k + "@", val)
    assert "@" not in body
    tikz("fig_pipeline", body)


def fig_pipeline_mpl():
    rec = num("e14_counter_reuse_census.txt", r"data-uplink receptions (\d+)")
    frames = num("e14_counter_reuse_census.txt", r"\(main\): (\d+) \(")
    copies = num("e14_counter_reuse_census.txt", r"absorbed (\d+) copies")
    ftrip = num("e14_counter_reuse_census.txt", r"with the gateway-aware merge \(main\): triples (\d+), addresses")
    faddr = num("e14_counter_reuse_census.txt", r"with the gateway-aware merge \(main\): triples \d+, addresses (\d+)")
    ex = num("e15b_reuse_analysis.txt", r"examined \(a testable pair\): (\d+)")
    ctrip = num("e15b_reuse_analysis.txt", r"triples with related or identical pairs: (\d+)")
    caddr = num("e15b_reuse_analysis.txt", r"confirmed addresses: (\d+)")
    unrel = num("e15b_reuse_analysis.txt", r"with only unrelated pairs: (\d+)")
    unres = num("e15b_reuse_analysis.txt", r"unresolved triples \(only identical pairs under 6 h\): (\d+)")
    unres_a = num("e15b_reuse_analysis.txt", r"no examined triple: (\d+)")
    f = lambda v: f"{v:,}"
    fig, ax = plt.subplots(figsize=(W, 4.3)); ax.set_xlim(0, 10); ax.set_ylim(0, 8.6); ax.axis("off")
    bw, bh, x0 = 5.6, 0.95, 0.2
    stages = [
        (7.45, f"Receptions: CRC-valid data uplinks, one row per gateway\nLoED {f(rec)}", FILL, MUTED),
        (6.05, f"Frames: same PHY payload, each reception within 60 s of the previous;\ncopies on unheard gateways within 6 h merged ({f(copies)})  →  {f(frames)}", FILL, MUTED),
        (4.65, f"Counter test: a (DevAddr, FCnt, size) triple with two frames\n≥ 10 min apart  →  {f(ftrip)} triples on {f(faddr)} addresses", "white", INK2),
        (3.25, f"Ciphertext test on every pair of equal FRMPayload length:\nrelated if P[Bin(8n, ½) ≤ k] < 10$^{{-6}}$, or identical ≥ 6 h apart\n{f(ex)} triples with a testable pair", "#dbe8f8", BLUE),
    ]
    for y, t, fc, ec in stages:
        box(ax, x0, y, bw, bh, t, fc=fc, ec=ec, size=8)
    for (y_a, *_), (y_b, *_) in zip(stages[:-1], stages[1:]):
        arrow(ax, x0 + bw / 2, y_a, x0 + bw / 2, y_b + bh)
    # outcomes
    yo, ow = 1.2, 1.78
    outs = [(f"Confirmed\n{f(ctrip)} triples\n{f(caddr)} addresses", "white", BLUE, "bold"),
            (f"Only unrelated pairs\n{f(unrel)} triples", "white", MUTED, "normal"),
            (f"Unresolved: identical\n< 6 h only\n{f(unres)} triples\n{f(unres_a)} further addresses", "white", MUTED, "normal")]
    for i, (t, fc, ec, wt) in enumerate(outs):
        xx = x0 + i * (ow + 0.13)
        box(ax, xx, yo, ow, 1.25, t, fc=fc, ec=ec, size=8, weight=wt, lw=1.1 if i == 0 else 0.8)
        arrow(ax, x0 + bw / 2, stages[-1][0], xx + ow / 2, yo + 1.25)
    # side panels: controls and validation
    sx, sw = 6.1, 3.7
    box(ax, sx, 4.65, sw, 2.35, "Controls (pairs that cannot share a keystream)\n• different addresses, same FCnt and size\n• one address, different counters\n• one address, adjacent counters\n→ 0 related in every control",
        fc="white", ec=ORANGE, size=7.8, ls=(0, (3, 2)))
    box(ax, sx, 1.2, sw, 3.0, "Validation (reuse that must be found)\n• detection power by payload length\n• synthetic fleet with known truth\n• Brno devices whose MICs verify under a\n   published default key: reuse certain\n• mutation test of the pipeline",
        fc="white", ec=AQUA, size=7.8, ls=(0, (3, 2)))
    arrow(ax, sx, 5.8, x0 + bw, 3.9, color=ORANGE, ls=(0, (3, 2))); arrow(ax, sx, 2.7, x0 + bw, 3.55, color=AQUA, ls=(0, (3, 2)))
    ax.text(x0, 0.6, "Counts for LoED (London); the same pipeline runs on the four city captures. No payload is decrypted.", fontsize=7.5, color=INK2)
    save(fig, "fig_pipeline")


# ------------------------------------------------------------------ Fig. 3: counter trace of one confirmed address
def fig_trace():
    T = pd.read_csv("results/fig_counter_trace.csv")
    n_all = len(T); T = T[pd.to_datetime(T.t, unit="s") >= pd.Timestamp("2020-04-25")].reset_index(drop=True)   # the 2020 block
    t = pd.to_datetime(T.t, unit="s"); f = T.fcnt.to_numpy()
    fig, ax = plt.subplots(figsize=(W, 2.45))
    nc = ~T.confirmed.to_numpy()
    ax.scatter(t[nc], f[nc], s=5, color=MUTED, lw=0, label="frame", zorder=2)
    ax.scatter(t[~nc], f[~nc], s=9, color=ORANGE, marker="D", lw=0, label="frame in a confirmed triple (counter repeated, related ciphertexts)", zorder=3)
    d = np.diff(f); nxt = np.r_[d[1:], -1]
    reset = (d < -64) & ~((f[:-1] >= 65536 - 1024) & (f[1:] < 1024)) & (nxt >= 0) & (nxt <= 64)
    for i in np.flatnonzero(reset):
        ax.axvline(t.iloc[i + 1], color=BLUE, lw=0.8, ls=(0, (3, 2)), zorder=1)
    ax.plot([], [], color=BLUE, lw=0.8, ls=(0, (3, 2)), label="counted counter reset")
    ax.set_ylabel("Frame counter (FCnt)"); ax.set_xlabel("Date (2020 capture block)")
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=3, fontsize=7.5, handletextpad=0.3, columnspacing=1.0)
    ax.set_ylim(bottom=-0.03 * f.max(), top=f.max() * 1.05)
    import matplotlib.dates as mdates
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    save(fig, "fig_trace")
    open("results/fig_trace_block.txt", "w", encoding="utf-8").write(
        f"trace address (results/fig_counter_trace.csv): frames {n_all}; in the 2020 block {len(T)}, of which in confirmed triples {int(T.confirmed.sum())}; "
        f"before it {n_all - len(T)}; counted resets inside the 2020 block {int(reset.sum())}\n")
    return int(reset.sum()), len(T), n_all - len(T), int(T.confirmed.sum()), t.min(), t.max()


# ------------------------------------------------------------------ Fig. 4: z-scores of examined pairs against placebo pairs
def fig_zscores():
    Z = pd.read_csv("results/fig_zscores.csv"); x = Z.z_left.to_numpy() + 0.125
    fig, ax = plt.subplots(figsize=(W, 2.6))
    for col, lab, c, ls in (("same_counter", "same DevAddr, FCnt and size (examined pairs)", BLUE, "-"),
                            ("placebo", "placebo: different addresses, same FCnt and size", ORANGE, "--")):
        y = Z[col].to_numpy() / Z[col].sum() / 0.25
        ax.step(x, np.where(y > 0, y, np.nan), where="mid", color=c, ls=ls, lw=1.2, label=lab)
    g = np.linspace(-8, 8, 400); ax.plot(g, np.exp(-g ** 2 / 2) / math.sqrt(2 * math.pi), color=MUTED, lw=0.8, ls=":", label="independent keystreams (normal limit)")
    zt = [(C.kstar(8 * n) - 4 * n) / math.sqrt(2 * n) for n in (12, 33)]
    ax.axvspan(-60, max(zt), color=BLUE, alpha=0.07, lw=0)
    ax.axvline(max(zt), color=BLUE, lw=0.7)
    ax.text(max(zt) - 0.4, 1.5e-5, "related at $10^{-6}$\n(z below about −4.8\nfor 12 to 33 bytes)", ha="right", va="bottom", fontsize=7.5, color=INK2)
    ax.set_yscale("log"); ax.set_ylim(1e-6, 1); ax.set_xlim(-18, 7)
    ax.set_xlabel("z = (k − 4n) / √(2n), k differing bits over n bytes"); ax.set_ylabel("Density of pairs")
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, fontsize=7.5, handlelength=2.2, columnspacing=1.2)
    save(fig, "fig_zscores")


# ------------------------------------------------------------------ Fig. 5: concentration of confirmed frames
def fig_concentration():
    Cn = pd.read_csv("results/fig_concentration.csv")
    fig, ax = plt.subplots(figsize=(W, 2.5))
    for cap, c, mk, ls in (("LoED", BLUE, "o", "-"), ("Brno", ORANGE, "s", "--"), ("Vienna", AQUA, "^", "-.")):
        g = Cn[Cn.capture == cap]; s = g.frames.to_numpy(); cum = np.cumsum(s) / s.sum() * 100; r = g["rank"].to_numpy()
        ax.plot(r, cum, color=c, ls=ls, marker=mk, ms=3.5, markevery=max(1, len(r) // 12), lw=1.3, label=f"{cap} ({len(r)} confirmed addresses)")
    ax.set_xscale("log"); ax.set_xlim(0.8, 300); ax.set_ylim(0, 103); ax.legend(loc="lower right", fontsize=7.5)
    ax.set_xlabel("Confirmed addresses ranked by frames in confirmed triples"); ax.set_ylabel("Cumulative share of frames (%)")
    ax.axvline(5, color=MUTED, lw=0.6, ls=":"); ax.text(5.3, 8, "top 5", fontsize=7.5, color=INK2)
    save(fig, "fig_concentration")


# ------------------------------------------------------------------ Fig. 6: sensitivity of the LoED count
def fig_sensitivity():
    rows = re.findall(r"^\s+(-\d+) \|\s+(\d+) s \|\s+(\d+) h \|\s+(\d+) \|", res("e21_threshold_sensitivity.txt"), re.M)
    S = pd.DataFrame(rows, columns=["thr", "mg", "ig", "addr"]).astype(int)
    fig, ax = plt.subplots(figsize=(W, 2.45))
    for (mg, ig), c, mk, ls, lab in (((600, 6), BLUE, "o", "-", "minimum gap 10 min (main)"), ((3600, 6), ORANGE, "s", "--", "minimum gap 1 h"),
                                     ((21600, 6), AQUA, "^", "-.", "minimum gap 6 h")):
        g = S[(S.mg == mg) & (S.ig == ig)].sort_values("thr", ascending=False)
        ax.plot(-g.thr, g.addr, color=c, marker=mk, ms=4, ls=ls, label=lab)
    m = S[(S.thr == -6) & (S.mg == 600) & (S.ig == 6)].addr.iloc[0]
    ax.annotate(f"main rule: {m}", (6, m), xytext=(6.4, m + 95), fontsize=7.5, color=INK, arrowprops=dict(arrowstyle="-", lw=0.6, color=INK2))
    ax.set_xticks([3, 6, 9, 12]); ax.set_xticklabels(["$10^{-3}$", "$10^{-6}$", "$10^{-9}$", "$10^{-12}$"])
    ax.set_xlabel("Relatedness threshold τ (identical gap 6 h)"); ax.set_ylabel("Confirmed LoED addresses"); ax.set_ylim(0, 600)
    ax.legend(loc="upper right", fontsize=7.5)
    save(fig, "fig_sensitivity")


# ------------------------------------------------------------------ Fig. 7: detection power
def fig_power():
    fig, ax = plt.subplots(figsize=(W, 2.45)); u = np.linspace(0, 1, 401)
    for n, c, ls, mk in ((8, ORANGE, "--", "s"), (12, BLUE, "-", "o"), (33, AQUA, "-.", "^")):
        k = C.kstar(8 * n)
        p = [1.0 if round((1 - x) * n) == 0 else (C.tail_p(k, 8 * round((1 - x) * n)) if k >= 0 else 0.0) for x in u]
        ax.plot(u, p, color=c, ls=ls, lw=1.3, label=f"{n}-byte FRMPayload")
    ax.axvline(0.55, color=MUTED, lw=0.7, ls=":"); ax.text(0.565, 0.04, "median measured\nunchanged share (0.55)", fontsize=7.5, color=INK2)
    ax.set_xlabel("Share of plaintext bytes unchanged between the two frames"); ax.set_ylabel("Probability the pair is related")
    ax.set_xlim(0, 1); ax.set_ylim(-0.02, 1.02); ax.legend(loc="center right", fontsize=7.5)
    save(fig, "fig_power")


# ------------------------------------------------------------------ Fig. 8: airtime cost of the fixes
def fig_airtime():
    D = pd.read_csv("results/e18_devices.csv"); D = D[D.resets > 0]
    fig, ax = plt.subplots(figsize=(W, 2.45)); rng = np.random.default_rng(0)
    cols = (("rejoin_share", "join on every reboot"), ("epoch2_cost", "2-byte epoch\nin every frame"), ("iv8_share", "8-byte random IV\nin every frame"))
    for i, (c, lab) in enumerate(cols):
        v = 100 * D[c].to_numpy(); xs = i + rng.uniform(-0.18, 0.18, len(v))
        ax.scatter(xs, v, s=6, color=BLUE, alpha=0.45, lw=0)
        med = np.median(v); ax.plot([i - 0.28, i + 0.28], [med, med], color=INK, lw=1.4)
        ax.text(i + 0.31, med, f"median {med:.2f}%", va="center", fontsize=7.5, color=INK)
    ax.set_yscale("log"); ax.set_xticks(range(3)); ax.set_xticklabels([l for _, l in cols]); ax.set_xlim(-0.5, 2.95)
    ax.set_ylabel("Added airtime (% of uplink airtime)"); ax.grid(axis="x", visible=False)
    save(fig, "fig_airtime")


if __name__ == "__main__":
    which = sys.argv[1:] or ["encryption", "pipeline", "trace", "zscores", "concentration", "power", "airtime"]   # sensitivity: Table 5 holds it
    for w in which:
        r = globals()["fig_" + w]()
        if r is not None: print(w, r)
