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
| `hash_entropy2.dart` | Whether a CRC-based filter hash carries 64 bits. Answer: no, 32 — 1868 collisions over 4M random keys against 1863 predicted by the birthday bound. This is what replaced the phase-1 CRC recommendation with CFH-64. |
| `hash_variants.dart`, `hash_entropy.dart` | False-positive rate of each hash candidate across five key shapes. |
| `cfh_check.dart` | That the signed Dart constants in `cfh64()` are the unsigned values the spec prints, plus entropy and FPR of the shipped function. |
| `p8_diag.dart` | Why an aged scan cost 2.14x while `locality_debt` read 0 %. Answer: 19 individually-sorted cold runs. |
| `p8_sweep.dart`, `p8_cost.dart` | The locality/space/write-amplification trade, and that a debt trigger holds the aged scan at 1.00x where a space trigger does not. |
| `dbg.dart` | Segment descent correctness across sizes; found the separator-bounds bug at height 3. |
