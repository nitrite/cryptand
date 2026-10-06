#!/usr/bin/env bash
# Release gate (PLAN.md M0.2). Usage: tools/gate.sh quick|full
# Exits non-zero on the first failing stage; prints the time per stage.
# Not gated on purpose: cargo fmt, clippy style lints.
set -uo pipefail
mode="${1:-}"; [[ $mode == quick || $mode == full ]] || { echo "usage: $0 quick|full" >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="$root/reference"

stage() {  # stage <name> <dir> <cmd...>
  local name=$1 dir=$2; shift 2
  printf '\n\033[1m== %s\033[0m\n' "$name"
  local t0=$SECONDS
  if (cd "$dir" && "$@"); then
    printf '   \033[32mok\033[0m   %s (%ds)\n' "$name" $((SECONDS - t0))
  else
    printf '   \033[31mFAIL\033[0m %s (%ds)\n' "$name" $((SECONDS - t0)); exit 1
  fi
}
# Stages whose tooling lands in a later milestone. Loud, so a missing control is visible.
pending() { printf '\n\033[33m== PENDING %s — not built yet (%s)\033[0m\n' "$1" "$2"; }

stage "rust test (debug)"   "$ref/rust" cargo test --workspace -q
stage "rust test (release)" "$ref/rust" cargo test --workspace --release -q
stage "rust clippy"         "$ref/rust" cargo clippy -q --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious
stage "oplog_gen tests"     "$ref/rust" cargo test -q -p cryptand --features harness --bin oplog_gen
stage "java verify"         "$ref/java" mvn -B -q verify
stage "dart analyze"        "$ref/dart/cryptand" dart analyze --fatal-infos
stage "dart test"           "$ref/dart/cryptand" dart test
stage "interop"             "$root" "$ref/conformance/interop/run.sh"

stage "oplog regress (rust)" "$ref/rust" sh -c 'cargo build -q --release -p cryptand --features harness --bin oplog_check && target/release/oplog_check ../conformance/oplog/regress/*.jsonl'
stage "oplog regress (java)" "$ref/java" mvn -B -q test -Djacoco.skip=true -Dtest=OplogCheckTest
stage "oplog regress (dart)" "$ref/dart/cryptand" dart test test/oplog_check_test.dart
stage "oplog hop (3 langs)"  "$root" sh -c 'tools/oplog_hop.sh --logs reference/conformance/oplog/hop/*.jsonl'
[[ -d $ref/conformance/files/fuzz-regress ]] || pending "fuzz regress replay" "M3.5"

if [[ $mode == full ]]; then
  pending "fuzz 60 s/target" "M3.1"
  pending "scale rung 10^6" "M6.1"
  pending "kill -9 x200/impl" "M2.2"
fi
printf '\n\033[32mgate %s: green (%ds)\033[0m\n' "$mode" "$SECONDS"
