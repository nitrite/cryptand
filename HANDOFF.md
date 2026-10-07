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

## Open questions for the human

(none)

## Next action

Hop seeds 0..300 encrypted (`nohup tools/oplog_hop.sh 0 300 --ops 400
--encrypted`), then the 10 000-seed runs of 1.2 (M1 Verify).

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
