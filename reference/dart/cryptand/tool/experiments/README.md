# Experiments

One-off scripts kept because `REPORT.md` cites their output as evidence. They
are excluded from `dart analyze` and are not part of the library.

| script | what it settled |
|---|---|
| `bloom_compare.dart` | Whether the filter's false-positive rate is a property of the hash or of *blocking*. Answer: blocking. Classic Bloom with the same hash lands on the textbook formula; blocked is 6.5x worse. |
| `bloom_curve.dart` | Whether raising `filter_bits_per_key` recovers the spec's 0.04 %. Answer: no — the curve flattens because `k` is clamped at 16. |
| `bloom_blocksize.dart` | Whether a larger block recovers it. Answer: only at a 4 KiB block, which defeats the one-cache-line probe that motivates blocking. |
| `proj.dart` | Where the cost of a single-field projection actually goes. Drove three portable optimizations. |
| `shape.dart` | Realized field-name and value averages of the benchmark document, against the shape `design/performance-model.md` section 1 assumes. |
| `dbg.dart` | Segment descent correctness across sizes; found the separator-bounds bug at height 3. |
