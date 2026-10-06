#!/bin/sh
# M1.3 cross-language hop: for seeds A..B-1, generate an op-log, cut it at its
# `reopen` lines (no snapshot is live there), and play the legs in turn on ONE
# file: Rust, Java, Dart, Rust, ... Then all three open the result and must
# print the same digest.
# tools/oplog_hop.sh A B [oplog_gen knobs...]   (e.g. --encrypted)
# tools/oplog_hop.sh --logs FILE.jsonl...       (committed logs, every rotation)
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
rel="$root/reference/rust/target/release"
(cd "$root/reference/rust" && cargo build -q --release -p cryptand --features harness --bin oplog_gen --bin oplog_check)
(cd "$root/reference/java" && mvn -B -q test-compile -Djacoco.skip=true &&
  mvn -B -q dependency:build-classpath -Dmdep.outputFile="$dir/cp" -Dmdep.includeScope=test)
jcp="$root/reference/java/target/classes:$root/reference/java/target/test-classes:$(cat "$dir/cp")"

leg() { # lang log db from to -> prints the digest, or fails
  case $1 in
    rust) out=$("$rel/oplog_check" --hop "$2" "$3" "$4" "$5" || true) ;;
    java) out=$(java -cp "$jcp" org.dizitart.cryptand.lsm.OplogCheckTest --hop "$2" "$3" "$4" "$5" || true) ;;
    dart) out=$(cd "$root/reference/dart/cryptand" &&
      OPLOG_HOP="$2 $3 $4 $5" dart test test/oplog_check_test.dart -N hop 2>&1 | grep -o 'ok digest.*\|FAIL.*' | head -1 || true) ;;
  esac
  case $out in
    "ok digest "*) echo "${out#ok digest }" ;;
    *) echo "seed $seed: $1 leg [$4,$5): ${out:-no output}" >&2; return 1 ;;
  esac
}

play() { # log db first-leg-index
  log=$1 db=$2
  rm -f "$db"
  end=$(($(wc -l < "$log") + 1))
  from=2 i=$3
  for cut in $(grep -n '"op":"reopen"' "$log" | cut -d: -f1) $end; do
    [ "$cut" -gt "$from" ] || continue
    case $((i % 3)) in 0) lang=rust ;; 1) lang=java ;; *) lang=dart ;; esac
    leg $lang "$log" "$db" $from $cut > /dev/null
    from=$cut i=$((i + 1))
  done
  # Every implementation reads the final file and agrees on the digest.
  r=$(leg rust "$log" "$db" $end $end) j=$(leg java "$log" "$db" $end $end) d=$(leg dart "$log" "$db" $end $end)
  if [ "$r" != "$j" ] || [ "$r" != "$d" ]; then
    echo "seed $seed: digests differ: rust $r java $j dart $d" >&2
    exit 1
  fi
}

if [ "$1" = --logs ]; then
  shift
  for seed in "$@"; do
    seed="$(cd "$(dirname "$seed")" && pwd)/$(basename "$seed")" # the dart leg runs elsewhere
    for first in 0 1 2; do play "$seed" "$dir/hop.cff" $first; done
  done
  echo "hop: $# log(s) x 3 rotations: 0 divergences"
  exit 0
fi
a=$1 b=$2; shift 2
seed=$a
while [ "$seed" -lt "$b" ]; do
  "$rel/oplog_gen" --seed "$seed" "$@" > "$dir/$seed.jsonl"
  play "$dir/$seed.jsonl" "$dir/$seed.cff" 0
  rm -f "$dir/$seed.jsonl" "$dir/$seed.cff"
  seed=$((seed + 1))
done
echo "hop: seeds $a..$b: 0 divergences"
