#!/usr/bin/env bash
# Runs the cross-language operational benchmark in all three implementations
# and prints one table. See README.md for what each row means -- and for the
# two rows that are NOT comparable between implementations.
#
#   reference/bench/run_all.sh [documents]
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref="$(cd "$here/.." && pwd)"
n="${1:-20000}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "building"
(cd "$ref/rust" && cargo build --release --quiet --bin ops_bench) || exit 1
(cd "$ref/java" && mvn -q -B compile) || exit 1

for impl in rust dart java; do
  say "$impl, $n documents"
  case "$impl" in
    rust) "$ref/rust/target/release/ops_bench" "$n" ;;
    dart) (cd "$ref/dart/cryptand" && dart run bench/ops.dart "$n") ;;
    java) java -cp "$ref/java/target/classes" \
            org.dizitart.cryptand.bench.OpsBench "$n" ;;
  esac | tee "$work/$impl.txt"
done

say "comparison"
python3 - "$work" <<'PY'
import os, sys
work = sys.argv[1]
impls = ["rust", "dart", "java"]
rows, kinds = {}, {}
for impl in impls:
    path = os.path.join(work, impl + ".txt")
    if not os.path.exists(path):
        continue
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, rest = line.partition("=")
        value = rest.split(" ", 1)[0]
        kind = "counter" if "kind=counter" in rest else "observation"
        rows.setdefault(name, {})[impl] = value
        kinds[name] = kind

w = max(len(k) for k in rows) if rows else 24
print(f"{'row'.ljust(w)} | {'rust'.rjust(14)} | {'dart'.rjust(14)} | "
      f"{'java'.rjust(14)} | kind")
print("-" * (w + 60))
for name, byimpl in rows.items():
    cells = " | ".join(byimpl.get(i, "-").rjust(14) for i in impls)
    print(f"{name.ljust(w)} | {cells} | {kinds[name]}")
print()
print("A `counter` row is a property of the workload. An `observation` is a")
print("property of this machine and this run, and is never asserted on.")
print("`point_read_page_reads` is not comparable BETWEEN implementations --")
print("see README.md; the three cache at different layers.")
PY
