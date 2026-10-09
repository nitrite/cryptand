#!/usr/bin/env python3
"""Seeds corpus/<target>/ from the shared conformance files and vectors (PLAN M3.1)."""
import hashlib, json, os, re

here = os.path.dirname(os.path.abspath(__file__))
conf = os.path.join(here, "../../../conformance")
hexre = re.compile(r"^(?:[0-9a-f]{2})+$")


def put(target, b):
    d = os.path.join(here, "corpus", target)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, hashlib.sha1(b).hexdigest()), "wb").write(b)


def strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from strings(v)


def vectors(path):
    return list(strings(json.load(open(os.path.join(conf, "vectors", path)))))


for target, path in [("cke_roundtrip", "cke/values.json"), ("cve_decode", "cve/values.json"),
                     ("wkb", "spatial/geometries.json")]:
    for s in vectors(path):
        if hexre.match(s):
            put(target, bytes.fromhex(s))
for s in vectors("analyzer/std_v1.json"):
    put("analyzer", s.encode())

manifest = json.load(open(os.path.join(conf, "files/manifest.json")))
for f in manifest["files"]:
    b = open(os.path.join(conf, "files", f["name"]), "rb").read()
    put("open_encrypted" if f["key"] else "open_file", b)
    put("superblock_keyslot", b[:4096])
    if not f["key"]:
        ps = f["page_size"]
        for p in range(2, len(b) // ps):
            if b[p * ps + 4] == 5:  # SEGMENT_HEADER: the whole extent it heads
                n = int.from_bytes(b[p * ps + 12:p * ps + 16], "little")
                put("segment", b[p * ps:(p + n) * ps])
