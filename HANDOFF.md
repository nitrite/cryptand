# HANDOFF — Cryptand 1.0 release

## State (2026-10-08, end of session 7)

- Branch `packaging/v1.0.0`. Manifests at 1.0.0, nothing published, no tags.
  Java targets Java 11 (built on JDK 17). Gate quick green 10-08 (see Log).
- M0 done. M1: hop 0..1000 plain and 0..300 encrypted clean; 10 000-seed
  M1.2 runs still pending. M2.1: fault sweeps 1000 seeds clean (Rust, Java).
- CI run 37760766268 (Java 21 macOS) failed on a POLICY finding after
  decrypt: Java conversion now clusters (F-088).
- **Conversion under a live snapshot** (human 10-08: Java matches Rust): Java's
  refusal removed. Both keep the dropped key(s) read-only while a snapshot may
  read a retired encrypted segment; Rust used to panic there (F-087).
- M2.2: the first ~110 kills per language found F-085 (Java backup resolved
  range-deleted values), F-086 (Java rotate raced its own background publish),
  F-087, and harness bugs (plain replay ran past `erase`; a kill inside
  `create()`; `os.remove` race), all fixed. Both kill runs were stopped; the
  5 000-kill runs need restarting on this build.
- M2.3: `tools/enospc.sh` (200 MB image, mobile profile). Rust passes plain and
  encrypted after F-090 (S0: every encrypted value-log rollover lost one
  value) and F-091 (S0: compaction ENOSPC mid manifest edit). Java: F-089,
  F-092 fixed; **F-093 open (S0)**: after ENOSPC, intermittently a pointer to a
  segment with no tree-7 entry on reopen, and work does not resume after
  freeing space.
- Open S1/S0 outside M5: **F-093**. M5: F-035, F-038, Dart halves of F-072,
  F-080, F-084 check, M2.2 Dart, F-075, F-079, F-081, F-087, F-088.
- Rust `stall_test` fails whenever another job fsyncs on /Volumes/External;
  never build Java while a hop or Java torture runs, nor edit sources
  while `tools/gate.sh` runs (its interop stage rebuilds Java).

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

- Commits this session bundle several findings each (shared files); the
  "one finding per commit" rule was bent. Fine, or split before the RC?
- F-093 (b): Java `desktop` cannot resume on a 200 MB device, because a
  reopened engine opens hot and cold 64 MiB value-log extents (spec 12 sizes
  desktop for 100 MB–100 GB). Accept as the profile's floor, or make Java
  extend value-log extents lazily as Rust does?

## Next action

Root-cause F-093 with `ENOSPC_JAVA_ONLY=1 tools/enospc.sh` (instrument
`PageFile.write` failures and tail allocations; both helped this session).
Then restart the M2.2 runs:
`nohup sh -c 'tools/torture.py rust 1000 3500 --ops 400 --maint 1; tools/torture.py rust 3500 6000 --ops 400 --maint 1 --encrypted' > reference/bench/runs/m22-rust.log 2>&1 &`
(and Java 101000–106000 likewise), shrink any failure, record numbers.

## Log

- 2026-10-06 — Survey, scope, M0.2 gate, M1.1–M1.3 (F-018…F-042). Details in git.
- 2026-10-07 — Hop sweeps, CI 26/26, F-043…F-077; M0 done; M2.1 fault seams; F-072 Rust + Java encrypt/decrypt. Details in git.
- 2026-10-08 — Java rotate; F-072 g in Rust+Java + interop step 12; F-075, F-077, F-078, F-079 (S0), F-081 (S0) fixed; F-080 found.
- 2026-10-08 — F-080 (S1) fixed in Rust + Java; gate quick green.
- 2026-10-08 — F-080 follow-up (Rust Database compaction), F-082/F-083/F-084 (S0) fixed; M2.2 harness; 5000-kill runs started.
- 2026-10-08 — CI fix (F-088); Java converts under snapshots (F-087); F-085, F-086 from M2.2; M2.3 harness: F-089–F-092 fixed, F-093 open.
