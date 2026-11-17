"""E29: upper bound on the time spanned by the transmissions of ONE LoRaWAN frame (repetitions set by NbTrans, at most 15, or retries of a
confirmed uplink), to justify the 6-hour identical gap. EU868, SF12 (the longest airtime), 125 kHz, CR 4/5, 8-symbol preamble (the Semtech
formula of E18); every transmission is followed by the full off-time of a 1% duty cycle (99 times its airtime), the longest wait the duty
cycle imposes. Usage: python -I src/scoping/e29_retransmission_span.py"""
import math


def air(pl, sf, bw=125e3):
    de = 1 if sf >= 11 else 0; ts = 2 ** sf / bw
    n = 8 + max(math.ceil((8 * pl - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * 5, 0)
    return (8 + 4.25 + n) * ts


for pl in (33, 64):
    a = air(pl, 12); off = 99 * a
    for k in (8, 15):
        print(f"PHY payload {pl} B at SF12: airtime {a:.2f} s, 1% duty-cycle off-time {off:.0f} s; {k} transmissions span at most {k * (a + off) / 60:.0f} min")
print("done")
