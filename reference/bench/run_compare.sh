#!/usr/bin/env bash
# The **comparison** tables: each implementation against the engines a person
# choosing a database in that language would actually weigh it against.
#
#   rust   cryptand vs fjall, redb, sled
#   java   cryptand vs MVStore, RocksDB, PalDB
#   dart   cryptand vs Hive
#
# These are a different question from `run_xlang_crud.sh`, which puts the three
# Cryptand implementations next to each other. Read `RESULTS.md` before reading
# any number here: the engines being compared do not all do the same amount of
# work, and the table says which.
#
# Every comparator is kept **out of the published artifact**: the Rust one is a
# separate crate excluded from the workspace, the Java ones are `test` scope,
# and the Dart one is a separate package.
#
#   reference/bench/run_compare.sh [documents] [mixed_ops]
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref="$(cd "$here/.." && pwd)"
n="${1:-20000}"
mixed="${2:-20000}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "rust -- cryptand against fjall, redb and sled"
(cd "$ref/rust" \
  && cargo build --release --quiet --manifest-path cryptand-compare/Cargo.toml \
  && ./cryptand-compare/target/release/compare_bench "$n" "$mixed")

say "java -- cryptand against MVStore, RocksDB and PalDB"
(cd "$ref/java" \
  && mvn -q -B test-compile -DskipTests \
  && mvn -q -B dependency:build-classpath -Dmdep.outputFile=/tmp/cryptand-bench-cp.txt \
  && java -cp "target/classes:target/test-classes:$(cat /tmp/cryptand-bench-cp.txt)" \
       org.dizitart.cryptand.bench.CompareBench "$n" "$mixed" 2>/dev/null)

say "dart -- cryptand against Hive"
(cd "$ref/dart/cryptand-compare" && dart pub get >/dev/null && dart run bin/compare.dart "$n" "$mixed")
