# HANDOFF — Cryptand 1.0 release

## State (2026-10-07, end of session 4)

- Branch `packaging/v1.0.0`, pushed to `origin`. Human 10-07: push every
  commit. Registries are set up (nitrite already publishes there).
- Three engines, Level 4 + encryption, in `reference/`; manifests at 1.0.0,
  nothing published, no tags. `tools/gate.sh quick` green (Maven on JDK 17).
- **Java targets Java 11** (`maven.compiler.release` 11, as nitrite-java;
  built on JDK 17). Records, sealed types, `instanceof` patterns and switch
  rules were ported to Java 11 source; `HexFormat` -> `util/Hex`. 336 tests
  pass on JDK 17, 25 and on a Java 11 JVM (`-Djvm=`). CI has a Java 11
  runtime job.
- **F-062:** Java's Unicode is a port of Rust's `unicode.rs` over the same
  15.1 tables (`text/unicode-15.1.0.bin`, regenerate with
  `tools/gen_java_unicode.py` from Rust's `unicode_tables.rs`). No JDK
  Unicode data is used any more.
- **Vectors:** `index/entries.json` 9 -> 12 cases (F-058 empty array, F-059
  unresolved traversal x2); all three suites read them.
- **CI 26/26 green** (run 37597698770): Linux/macOS/Windows × Rust stable+1.89,
  JDK 17/21/25 + Java 11 runtime, Dart 3.5+stable, interop ×3, cargo-deny.
  On the way: F-063 (Windows: `posio`, Dart lock byte, sidecar retry), F-064,
  F-066 (Java restore race), F-068 (Java untyped errors on damaged input).
- **F-065** from hop seed 451: COW `publish` leaked a page whenever a remove
  emptied a non-root page (Rust and Dart; Java rebuilds trees whole).
- M1.5 index differential in all three; **hop seeds 0..1000 plain clean**.
- **F-067 fixed:** all three lock the one byte at 2^62 (spec 01 §10 now says
  so); interop step 6 checks it on Unix. Rust's Windows `LockFileEx` path is
  only checked by CI. Open: M5: F-035, F-038, F-048's Dart verify leak report (S3).
- **Hop 0..300 encrypted clean** (10-07; seed 286 re-run alone after a
  concurrent `mvn` broke its Java leg — never build Java while hop runs).
- **M2.1 started (Rust):** `src/fault.rs` behind feature `faults` (tests only,
  enabled via a self dev-dependency): power cut drops/tears un-fsynced writes,
  fsync EIO, ENOSPC. `tests/fault_test.rs`: 1000 seeds × 3 sweeps clean
  (`CRYPTAND_FAULT_SEEDS=0..1000`, ~10 min release); lying-fsync control fails.
  Found **F-069 (S0, fixed in all three)**: slot B looked up at 4096 when slot A
  is bad; and F-070 (S3, Rust verify).
- **M2.1 Java:** `PageFile.Hook` (package-private) + test-tree `container.Faults`/
  `FaultTest` (`-Dcryptand.fault.seeds=0..1000`, ~15 min): 1000 seeds × 3 clean.
  Found **F-071 (S0)**: no barrier before Java's superblock write (fixed; one
  more fsync per commit, re-measure in M6); Dart's whole-file `save` is the same
  class, left to M5. Dart fault layer waits for M5.
- Rust `stall_test` fails whenever another job is fsyncing on /Volumes/External;
  run the gate on a quiet disk.

## Decisions already made (human)

- 10-06: scope = the three engine packages; Dart storage rewrite (M5) on
  `dart-storage`, go/no-go Fri 10-23 else Dart ships `1.0.0-rc.1`; freeze
  Tue 10-27, tags Fri 10-30.
- 10-06: F-042 — range-delete `end_key` is `CKE(end)`, no `tree_id`.
- 10-07: Java matches nitrite-java (`--release 11`, built on JDK 17); Java
  ships its own Unicode 15.1 tables; F-058/F-059 get conformance vectors.
- 10-07: F-067 approved — writer lock = one byte at 2^62, in spec 01 §10.
- 10-07: push every commit. Soak (M6.7) runs on the remote Mac
  (`anindya@207.254.39.186`) when it is free, never here. It was busy 10-07
  (llama-server at 96 % CPU) and has no Dart SDK; Rust and Java soak only.
- 10-07: F-072 — implement all of 13 §5 (encrypt/decrypt, rotate_master_key,
  add/remove_key, crypto_erase, cluster) in all three for 1.0; Dart's in M5.
  Rotation = copy-and-swap (fresh master into a sibling file, rename over);
  no format change; spec 14 §8.3/§8.4 get a note.
- 10-07: F-069 approved — spec 01 §2.1 step 1 probes slot B at every legal page size.

## Open questions for the human

(none)

## Next action

F-072 b (PLAN "F-072" section): Rust in-place `encrypt()` + `convert_step()`,
with a half-converted-file test that drives c. Then M2.2 kill -9 torture
(its op list now includes these). The 10 000-seed M1.2 runs still pending.

## Log

- 2026-10-06 — Survey, baseline, scope; M0.2 gate; M1.1 op-log; M1.2 Rust (F-018…F-022).
- 2026-10-06 — M1.2 Java checker; F-026…F-029.
- 2026-10-06 — Java clean (F-030/31/34/36/37/40), Dart checker (F-032/33/39), F-041, M1.3 hop → F-042.
- 2026-10-07 — Hop sweeps: F-043…F-051 across all three; hop 50 plain + 20 enc clean; gate green.
- 2026-10-07 — Final-code sweeps; F-052 (suspect), F-053 (F-029 in Rust/Dart), F-054, F-055; hop 0..150 plain + 0..40 enc clean.
- 2026-10-07 — F-052 root-caused and fixed (S0, Java seal during recount); F-056 (Dart live_records < 0) from hop seed 151.
- 2026-10-07 — Pushed; M0.5 CI matrix (F-061…F-064); M1.5 index differential (F-057…F-059); F-060 from hop seed 289.
- 2026-10-07 — Own Unicode tables in Java, Java 11 target, F-058/F-059 vectors; F-062…F-064 fixed; F-065 from hop seed 451.
- 2026-10-07 — CI 26/26 green (F-066, F-068 on the way); hop 0..1000 plain clean; M0 done.
- 2026-10-07 — F-067: one writer-lock byte (2^62) in all three + spec 01 §10; interop lock step.
- 2026-10-07 — Hop 0..300 enc clean; M2.1 Rust fault seam, 3000 fault seeds clean; F-069 (S0, all three), F-070.
- 2026-10-07 — Spec 01 §2.1 (F-069 approved); M2.1 Java fault seam, 3000 seeds clean; F-071 (S0, Java barrier; Dart → M5).
- 2026-10-07 — F-072 (S1) found scoping M2.2: 13 §5 MUSTs missing; human: implement all; Rust key ops done; design in PLAN.
