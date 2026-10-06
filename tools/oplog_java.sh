#!/bin/sh
# M1.2 Java: generate seeds A..B-1 with Rust oplog_gen, replay them in Java.
# tools/oplog_java.sh A B [oplog_gen knobs...]
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
a=$1 b=$2; shift 2
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
(cd "$root/reference/rust" && cargo build -q --release -p cryptand --features harness --bin oplog_gen)
s=$a
while [ "$s" -lt "$b" ]; do
  "$root/reference/rust/target/release/oplog_gen" --seed "$s" "$@" > "$dir/$s.jsonl"
  s=$((s + 1))
done
cd "$root/reference/java"
mvn -B -q test -Djacoco.skip=true -Dtest=OplogCheckTest#generatedLogsReplay -Doplog.dir="$dir" ${OPLOG_JAVA_OPTS:-}
echo "java: seeds $a..$b: 0 divergences"
