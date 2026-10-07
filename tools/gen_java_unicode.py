#!/usr/bin/env python3
"""Writes Java's Unicode tables resource from Rust's generated unicode_tables.rs,
so all three implementations read one dataset (Unicode 15.1, spec 07 §2.2).

tools/gen_java_unicode.py   (rerun whenever unicode_tables.rs is regenerated)

Format: b"CRYU", then per table in TABLES order: u32be count, count x u32be.
"""
import re, struct, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
src = (root / "reference/rust/cryptand/src/unicode_tables.rs").read_text()
TABLES = ["WB_RANGES", "EXTENDED_PICTOGRAPHIC", "ALPHABETIC", "NUMERIC_TYPE", "CCC_MAP",
          "SIMPLE_LOWERCASE", "DECOMP_FLAT", "COMPOSITION_EXCLUSIONS"]
out = bytearray(b"CRYU")
for name in TABLES:
    m = re.search(r"pub const %s: \[u32; (\d+)\] = \[(.*?)\];" % name, src, re.S)
    vals = [int(x, 0) for x in m.group(2).replace("\n", " ").split(",") if x.strip()]
    assert len(vals) == int(m.group(1)), name
    out += struct.pack(">I", len(vals)) + struct.pack(">%dI" % len(vals), *vals)
dst = root / "reference/java/src/main/resources/org/dizitart/cryptand/text/unicode-15.1.0.bin"
dst.write_bytes(bytes(out))
print(dst, len(out), "bytes")
