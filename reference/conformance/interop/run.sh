#!/usr/bin/env bash
# The mandatory round-trip gate of `spec/11-conformance.md` §6:
#
#   "for each golden file, open it in implementation A, mutate it, close it,
#    open it in B, verify, mutate, close, reopen in A. **This is the actual
#    product claim and it must be tested as such**, in CI, on every SDK's every
#    commit."
#
# Run from anywhere: ./reference/conformance/interop/run.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ref="$(cd "$here/../.." && pwd)"
rust="$ref/rust"
dart="$ref/dart/cryptand"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

RUST="$rust/target/release/interop"
fail=0
step=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

run_impl() {
  local impl="$1"; shift
  case "$impl" in
    rust) "$RUST" "$@" ;;
    dart) (cd "$dart" && dart run tool/interop.dart "$@") ;;
    *) echo "unknown implementation $impl" >&2; return 2 ;;
  esac
}

field() { grep -E "^$2=" <<<"$1" | head -1 | cut -d= -f2-; }

# One direction of the gate. $1 is the writer, $2 the reader; the reader must
# agree on the digest, then mutate, and the writer must agree on the result.
round_trip() {
  local a="$1"
  local b="$2"
  local file="$work/$a-to-$b.cryptand"
  step=$((step + 1))
  say "$step. $a writes, $b reads, $b mutates, $a reads"

  run_impl "$a" write "$file" >/dev/null || { bad "$a could not write"; return; }
  local produced
  produced="$(run_impl "$a" read "$file")" || { bad "$a could not read its own file"; return; }
  local d0; d0="$(field "$produced" digest)"
  ok "$a wrote $(field "$produced" docs) documents, digest $d0"

  local seen
  seen="$(run_impl "$b" read "$file")" || { bad "$b could not open a file $a wrote"; return; }
  local d1; d1="$(field "$seen" digest)"
  if [[ "$d0" == "$d1" ]]; then
    ok "$b read the same digest $d1 from ${a}'s file"
  else
    bad "$b read digest $d1, $a wrote $d0"
  fi
  [[ "$(field "$seen" docs)"          == "$(field "$produced" docs)" ]]          || bad "document count differs"
  [[ "$(field "$seen" dict)"          == "$(field "$produced" dict)" ]]          || bad "name dictionary differs"
  [[ "$(field "$seen" index_de)"      == "$(field "$produced" index_de)" ]]      || bad "the index answers differently"
  [[ "$(field "$seen" page_size)"     == "$(field "$produced" page_size)" ]]     || bad "page_size differs"
  [[ "$(field "$seen" writer)"        == "$(field "$produced" writer)" ]]        || bad "writer_id differs"
  ok "$b agrees on documents, dictionary, index and page size"

  # `13-operations.md` §9 / `01-container.md` §9: the reader's own verification
  # pass over a file it did not write. Leaks are repairable and are not a
  # failure of the format; corruption and tampering are.
  run_impl "$b" verify "$file" >"$work/verify-$a-$b.txt" 2>&1
  local leaks
  leaks="$(grep -c 'Leak:' "$work/verify-$a-$b.txt" || true)"
  if grep -qE 'Corruption|Tampering' "$work/verify-$a-$b.txt"; then
    bad "$b found corruption or tampering in ${a}'s file"
    sed 's/^/        /' "$work/verify-$a-$b.txt" | head -8
  elif [[ "$leaks" -gt 0 ]]; then
    ok "$b verified ${a}'s file: no corruption, $leaks repairable leaks"
  else
    ok "$b verified ${a}'s file clean"
  fi

  run_impl "$b" mutate "$file" "$b" >/dev/null || { bad "$b could not mutate ${a}'s file"; return; }
  local after_b; after_b="$(run_impl "$b" read "$file")" || { bad "$b could not re-read"; return; }
  local d2; d2="$(field "$after_b" digest)"
  [[ "$d2" != "$d0" ]] || bad "the mutation changed nothing, so the test proves nothing"
  ok "$b mutated it to $(field "$after_b" docs) documents, digest $d2"

  local back
  back="$(run_impl "$a" read "$file")" || { bad "$a could not reopen after ${b}'s mutation"; return; }
  local d3; d3="$(field "$back" digest)"
  if [[ "$d2" == "$d3" ]]; then
    ok "$a reads back exactly what $b wrote: digest $d3"
  else
    bad "$a read $d3 where $b wrote $d2"
  fi
  [[ "$(field "$back" dict)" == "$(field "$after_b" dict)" ]] \
    || bad "the field name $b added is not visible to $a"
  ok "the field name $b added to the dictionary is visible to $a"

  # And once more, so the file has been mutated by both.
  run_impl "$a" mutate "$file" "$a" >/dev/null || { bad "$a could not mutate"; return; }
  local final_a final_b
  final_a="$(run_impl "$a" read "$file")"; final_b="$(run_impl "$b" read "$file")"
  if [[ "$(field "$final_a" digest)" == "$(field "$final_b" digest)" ]]; then
    ok "after mutations by both, they agree: digest $(field "$final_a" digest)"
  else
    bad "after both mutated: $a says $(field "$final_a" digest), $b says $(field "$final_b" digest)"
  fi
}

say "building"
(cd "$rust" && cargo build --release -p cryptand -q) || { echo "cargo build failed"; exit 1; }
[[ -x "$RUST" ]] || { echo "missing $RUST"; exit 1; }
ok "rust: $($RUST 2>&1 | head -1 >/dev/null; echo built)"

round_trip rust dart
round_trip dart rust

say "result"
if [[ $fail -eq 0 ]]; then
  printf '   \033[32mthe round-trip gate passes in both directions\033[0m\n'
else
  printf '   \033[31mthe round-trip gate FAILED\033[0m\n'
fi
exit $fail
