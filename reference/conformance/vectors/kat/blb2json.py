"""Turn RustCrypto's Wycheproof .blb extracts into the shared KAT JSON.

ponytail: one-off converter, kept so the JSON can be regenerated and checked.
Usage: python3 -I blb2json.py <file.blb> <fields,comma,separated> > out.json
"""
import json, sys

def vlq(b, i):
    n = b[i]; v = n & 0x7F; i += 1
    while n & 0x80:
        n = b[i]; v = ((v + 1) << 7) + (n & 0x7F); i += 1
    return v, i

def blobs(b):
    n, i = vlq(b, 0); dedup = []
    for _ in range(n):
        l, i = vlq(b, i); dedup.append(b[i:i + l]); i += l
    out = []
    while i < len(b):
        v, i = vlq(b, i)
        if v & 1: out.append(dedup[v >> 1])
        else: l = v >> 1; out.append(b[i:i + l]); i += l
    return out

data = open(sys.argv[1], 'rb').read()
fields = sys.argv[2].split(',')
bl = blobs(data)
assert len(bl) % len(fields) == 0, (len(bl), len(fields))
rows = [dict(zip(fields, (x.hex() for x in bl[k:k + len(fields)])))
        for k in range(0, len(bl), len(fields))]
json.dump(rows, sys.stdout, indent=0); print()
