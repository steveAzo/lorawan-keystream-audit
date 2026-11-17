"""E26b: share of all CRC-valid packets (all three concentrators, all message types) that verify under Semtech's published default key, counting
data uplinks AND data downlinks, to reconcile E26 with Povalac et al.'s figure (15.5% of all valid Brno packets, 0.2% in Vienna), which counts
packets of ABP devices using the key. Downlink MIC: B0 with direction 1 and the downlink counter; upper 16 counter bits 0 to 3 are tried.
Only the 4-byte MIC is computed; no payload is decrypted and no address is printed.
Usage (from the repository root): python -I src/scoping/e26b_default_key_downlinks.py <log.zip> <city_log> ..."""
import base64, os, sys, zipfile
from collections import Counter
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"))
from parse_povalac import rows

KEY = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")


def mic(r, fc32, d):
    msg = r[:-4]
    b0 = bytes([0x49, 0, 0, 0, 0, d]) + r[1:5] + fc32.to_bytes(4, "little") + bytes([0, len(msg)])
    c = CMAC(algorithms.AES(KEY)); c.update(b0 + msg)
    return c.finalize()[:4] == r[-4:]


for member in sys.argv[2:]:
    zf = zipfile.ZipFile(sys.argv[1]); n = 0; ver = Counter(); seen = Counter()
    for t, b64, datr, g in rows(zf, member):
        r = base64.b64decode(b64 + "=" * (-len(b64) % 4)); n += 1
        mt = r[0] >> 5
        if mt not in (2, 3, 4, 5) or len(r) < 12 or r[0] & 0x1F: continue
        d = 0 if mt in (2, 4) else 1; fc = int.from_bytes(r[6:8], "little"); seen[d] += 1
        if any(mic(r, (hi << 16) | fc, d) for hi in range(4)): ver[d] += 1
    tot = ver[0] + ver[1]
    print(f"{member}: CRC-valid packets {n}; verifying under the Semtech key: data uplinks {ver[0]} of {seen[0]}, data downlinks {ver[1]} of {seen[1]}; "
          f"together {tot} ({tot / max(n, 1):.1%} of CRC-valid packets)", flush=True)
print("done")
