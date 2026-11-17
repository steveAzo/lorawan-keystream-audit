"""E20: ground-truth validation of the ciphertext relatedness detector on a synthetic fleet encrypted with the real LoRaWAN 1.0.x FRMPayload scheme.
Payload encryption per the LoRaWAN spec: keystream block i = AES128(AppSKey, 0x01 | 0x00*4 | Dir | DevAddr(LE) | FCnt32(LE) | 0x00 | i), XOR with the plaintext.
Device types (so the truth is known): T1 OTAA, counter kept (no reuse); T2 ABP, no resets (no reuse); T3 ABP with counter resets (reuse);
T4 OTAA rejoin after each reboot keeping the same DevAddr, fresh keys, counter restarts (no reuse; counter-rollback false alarm);
T5 two devices sharing a DevAddr with different keys (no reuse; false alarm); T6 stuck counter with the same key (reuse).
Plaintext: a per-device share u0 of constant bytes, the rest uniformly random on each frame (the hardest case for detection).
Capture: each frame is heard with probability c. Detectors: counter test (same addr, FCnt, size, >= 10 min apart) and ciphertext test (binomial lower tail < 1e-6, or identical >= 6 h apart).
Usage: python -I src/scoping/e20_ground_truth_sim.py [seed] [capture probabilities ...] [mut=m1|m2|m3]
Mutants (for src/scoping/e25_mutation_sim.py): m1 test direction flipped (flags pairs NOT below the threshold);
m2 threshold relaxed to 0.3; m3 ciphertexts compared with a one-byte offset.
Note: this script restates the detector instead of calling audit_common.py: its own pair loop with a 10-frame cap (the
real-data pipeline uses 80), no merging of receptions and no gateways (the fleet has none), and no length guard (lengths are equal by construction).
It tests the statistic, not the real-data pipeline."""
import math
import numpy as np, pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys
MUT = next((x[4:] for x in sys.argv[1:] if x.startswith("mut=")), None)
ARGS = [x for x in sys.argv[1:] if not x.startswith("mut=")]
SEED = int(ARGS[0]) if ARGS else 20
CS = tuple(float(x) for x in ARGS[1:]) or (0.25, 0.5, 0.72, 0.9)
THR = 0.3 if MUT == "m2" else 1e-6
if MUT: print("MUTANT", MUT)
rng = np.random.default_rng(SEED)
DAYS, PER_DAY = 90, 12
def keystream(key, addr, fcnt, n):
    blocks = b"".join(bytes([1, 0, 0, 0, 0, 0]) + addr.to_bytes(4, "little") + fcnt.to_bytes(4, "little") + bytes([0, i + 1]) for i in range((n + 15) // 16))
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(blocks)[:n]
types = [("T1", 150), ("T2", 80), ("T3", 80), ("T4", 60), ("T5", 40), ("T6", 25)]
LENS = rng.choice([8, 12, 20, 24, 40], size=1000, p=[.10, .20, .50, .10, .10])
rows = []; dev_id = 0
def new_dev(): 
    global dev_id; dev_id += 1; return dev_id
used = set()
def addr():
    while True:
        a = int(rng.integers(1, 2**32 - 1))
        if a not in used: used.add(a); return a
pair_addr = None
for ty, cnt in types:
    for k in range(cnt):
        n = int(rng.choice(LENS)); u0 = float(rng.choice([.3, .5, .7])); const = rng.integers(0, 256, n, dtype=np.uint8); mask = rng.random(n) < u0
        key = bytes(rng.integers(0, 256, 16, dtype=np.uint8)); a = addr()
        if ty == "T5":
            if k % 2 == 0: pair_addr = a
            else: a = pair_addr
        did = new_dev(); fcnt = 0; keyid = did
        nxt = rng.exponential(15 * PER_DAY) if ty in ("T3", "T4", "T6") else 1e18
        stuck = 0
        for f in range(DAYS * PER_DAY):
            t = (f / PER_DAY) * 86400 + rng.uniform(0, 600) + (k % 7) * 60
            if f >= nxt:
                if ty == "T3": fcnt = 0
                elif ty == "T4": fcnt = 0; key = bytes(rng.integers(0, 256, 16, dtype=np.uint8)); keyid = (did, f)
                elif ty == "T6": stuck = int(rng.integers(3, 15))
                nxt = f + rng.exponential(15 * PER_DAY)
            pt = np.where(mask, const, rng.integers(0, 256, n, dtype=np.uint8)).astype(np.uint8)
            ks = np.frombuffer(keystream(key, a, fcnt, n), np.uint8)
            rows.append((a, fcnt & 0xFFFF, n, t, (pt ^ ks).tobytes(), hash(keyid) & 0x7FFFFFFF, ty, u0))
            if stuck > 0: stuck -= 1
            else: fcnt += 1
F = pd.DataFrame(rows, columns=["addr", "fcnt", "n", "t", "ct", "key", "type", "u0"])
print("frames:", len(F), " devices:", dev_id, " addresses:", F.addr.nunique())
def cdf(k, nb): return sum(math.exp(math.lgamma(nb + 1) - math.lgamma(i + 1) - math.lgamma(nb - i + 1) - nb * math.log(2)) for i in range(min(k, nb) + 1))
def run(c):
    X = F[rng.random(len(F)) < c]
    res = []
    for (a, f, n), g in X.groupby(["addr", "fcnt", "n"], sort=False):
        if len(g) < 2: continue
        t = g.t.to_numpy(); b = list(g.ct); kk = g.key.to_numpy()
        counter = False; cipher = False; truth = False
        for i in range(min(len(b), 10)):
            for j in range(i + 1, min(len(b), 10)):
                if abs(t[j] - t[i]) < 600: continue
                counter = True
                if kk[i] == kk[j] and b[i] != b[j] or (kk[i] == kk[j] and abs(t[j] - t[i]) >= 6 * 3600): truth = True
                if b[i] == b[j]:
                    if abs(t[j] - t[i]) >= 6 * 3600: cipher = True
                    continue
                bi, bj = (b[i][1:], b[j][:-1]) if MUT == "m3" else (b[i], b[j])
                k = bin(int.from_bytes(bytes(x ^ y for x, y in zip(bi, bj)), "big")).count("1")
                nbits = 8 * len(bi)
                if (cdf(k, nbits) >= THR) if MUT == "m1" else (cdf(k, nbits) < THR): cipher = True
        if counter: res.append((a, f, n, g.u0.iloc[0], g.type.iloc[0], counter, cipher, truth))
    return pd.DataFrame(res, columns=["addr", "fcnt", "n", "u0", "type", "counter", "cipher", "truth"])
for c in CS:
    R = run(c)
    tp_c = (R.counter & R.truth).sum(); tp_k = (R.cipher & R.truth).sum()
    print(f"\ncapture probability {c}: groups flagged by counter test {R.counter.sum()}, true reuse groups {R.truth.sum()}")
    print(f"  counter test : precision {tp_c/max(R.counter.sum(),1):.1%}  recall {tp_c/max(R.truth.sum(),1):.1%}")
    print(f"  ciphertext   : precision {tp_k/max(R.cipher.sum(),1):.1%}  recall {tp_k/max(R.truth.sum(),1):.1%}  (false positives {(R.cipher & ~R.truth).sum()})")
    Aq = R.groupby("addr").agg(truth=("truth", "any"), cipher=("cipher", "any"))
    print(f"  ADDRESS-LEVEL at c={c}: true reuse addresses {int(Aq.truth.sum())}, found {int((Aq.truth & Aq.cipher).sum())} (recall {(Aq.truth & Aq.cipher).sum()/Aq.truth.sum():.1%}), false {int((Aq.cipher & ~Aq.truth).sum())}")
    if c == 0.72:
        T = R[R.truth]
        print("  ciphertext recall by plaintext-constant share u0:", T.groupby("u0").cipher.mean().round(3).to_dict())
        print("  ciphertext recall by payload length n:", T.groupby("n").cipher.mean().round(3).to_dict())
        Au = R[R.truth].groupby("addr").agg(u0=("u0", "first"), n=("n", "first"), cipher=("cipher", "any"))
        print("  address-level recall by u0:", Au.groupby("u0").cipher.mean().round(3).to_dict(), " by n:", Au.groupby("n").cipher.mean().round(3).to_dict(), " counts by u0:", Au.groupby("u0").size().to_dict())
        A = R.groupby("addr").agg(truth=("truth", "any"), cipher=("cipher", "any"), counter=("counter", "any"))
        print(f"  address level: true reuse addresses {int(A.truth.sum())}, ciphertext finds {int((A.truth & A.cipher).sum())} ({(A.truth & A.cipher).sum()/A.truth.sum():.0%}), counter test flags {int(A.counter.sum())} (precision {(A.counter & A.truth).sum()/A.counter.sum():.0%}), ciphertext precision {(A.cipher & A.truth).sum()/max(A.cipher.sum(),1):.0%}")
