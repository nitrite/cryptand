#!/usr/bin/env bash
# The like-for-like cross-language CRUD matrix: the same workload, driven at the
# **engine** level, in all three implementations.
#
# `run_all.sh` beside this runs `ops.rs` / `ops.dart` / `OpsBench`, which drive a
# `Collection` and build and encode a document inside the timed loop, and whose
# rows README.md says are not comparable between implementations. This one is
# the exception that is: same document encoded before the clock starts, same
# key, same profile, same durability, same phase sizes, same pseudo-random
# sequence bit for bit.
#
# What is still not the same is the **storage model**, and it is printed as a
# row rather than left to be discovered. See the Java bench's class docs.
#
#   reference/bench/run_xlang_crud.sh [documents] [mixed_ops]
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref="$(cd "$here/.." && pwd)"
n="${1:-20000}"
mixed="${2:-20000}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "building"
# `--features harness`: gated off by default, so the benchmarks are not
# binaries of the published crate. See `cryptand/Cargo.toml`.
(cd "$ref/rust" && cargo build --release --quiet --features harness --bin xlang_crud_bench) || exit 1
# `test-compile`: the benchmarks are test-scope so they do not ship in the jar.
(cd "$ref/java" && mvn -q -B test-compile -DskipTests) || exit 1

for impl in rust dart java; do
  say "$impl, $n documents"
  case "$impl" in
    rust) "$ref/rust/target/release/xlang_crud_bench" "$n" "$mixed" ;;
    dart) (cd "$ref/dart/cryptand" && dart run bench/xlang_crud.dart "$n" "$mixed") ;;
    java) java -cp "$ref/java/target/classes:$ref/java/target/test-classes" \
            org.dizitart.cryptand.bench.XlangCrudBench "$n" "$mixed" ;;
  esac | tee "$work/$impl.txt"
done

say "comparison"
python3 - "$work" <<'PY'
import os, sys
work = sys.argv[1]
impls = ["rust", "dart", "java"]
rows = {}
for impl in impls:
    path = os.path.join(work, impl + ".txt")
    if not os.path.exists(path):
        continue
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, rest = line.split("=", 1)
        rows.setdefault(name, {})[impl] = rest.split(" unit=")[0]

order = ["create_ops_per_s", "read_ops_per_s", "update_ops_per_s",
         "delete_ops_per_s", "mixed_ops_per_s", "persist_ms", "file_bytes",
         "storage_model"]
w = max(len(k) for k in order)
print(f"{'row'.ljust(w)} | {'rust'.rjust(14)} | {'dart'.rjust(14)} | {'java'.rjust(14)}")
print("-" * (w + 3 + 16 * 3))
for name in order:
    got = rows.get(name, {})
    cells = " | ".join(got.get(i, "-").rjust(14) for i in impls)
    print(f"{name.ljust(w)} | {cells}")
print()
print("ops/s rows measure engine work up to the segment build, which is the part")
print("all three do. `persist_ms` is what making the result durable costs once, and")
print("it is not the same operation in all three -- read `storage_model`.")
PY
