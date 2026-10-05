Resuming work: read `HANDOFF.md`, then `PLAN.md`, before anything else. Update `HANDOFF.md` before the session ends.

# Cryptand

A cross-language storage engine and file format: one spec (`spec/`), three
independent implementations in `reference/` (Rust, Java, Dart) that must read
and write each other's files.

- **The spec is normative**, not any implementation. The format is frozen at
  CFF v1.0: any change to bytes on disk, a MUST, or a conformance vector needs
  the human's approval first.
- **Fix it in all three.** A bug found in one implementation is checked in
  the other two; `FINDINGS.md` records R/J/D for each row.
- Findings go in `FINDINGS.md` (F-NNN). History stays in `reference/HARDENING.md`
  and the REPORTs.
- Never commit red. Gate: `tools/gate.sh quick` (after PLAN M0.2 lands it).

## Commands

```bash
cd reference/rust && cargo test --workspace && cargo test --workspace --release
cd reference/java && mvn -B verify
cd reference/dart/cryptand && dart analyze --fatal-infos && dart test
reference/conformance/interop/run.sh          # cross-language round-trip gate (repo root)
```

Benchmarks: `reference/bench/` (`run_compare.sh`, `run_xlang_crud.sh`). Rust
harness binaries need `--features harness`. Long jobs run under `nohup`, with
logs in `reference/bench/runs/` (git-ignored).
