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
java="$ref/java"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

RUST="$rust/target/release/interop"
# `target/test-classes` too: the interop harness is test-scope, so that it does
# not ship in the published jar. See `reference/bench/README.md`.
JAVA_CP="$java/target/classes:$java/target/test-classes"
fail=0
step=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

# `spec/14-security.md` §3.3's `kdf = 0` credential. Empty for the plaintext
# directions; set for the encrypted ones.
KEY=""

run_impl() {
  local impl="$1"; shift
  local extra=()
  [[ -n "$KEY" ]] && extra=(--key "$KEY")
  case "$impl" in
    rust) "$RUST" "$@" ${extra[@]+"${extra[@]}"} ;;
    dart) (cd "$dart" && dart run tool/interop.dart "$@" ${extra[@]+"${extra[@]}"}) ;;
    java) java -cp "$JAVA_CP" org.dizitart.cryptand.tool.Interop "$@" ${extra[@]+"${extra[@]}"} ;;
    *) echo "unknown implementation $impl" >&2; return 2 ;;
  esac
}

field() { grep -E "^$2=" <<<"$1" | head -1 | cut -d= -f2-; }

# One direction of the gate. $1 is the writer, $2 the reader; the reader must
# agree on the digest, then mutate, and the writer must agree on the result.
round_trip() {
  local a="$1"
  local b="$2"
  local file="$work/$a-to-$b${KEY:+-enc}.cryptand"
  step=$((step + 1))
  say "$step. $a writes, $b reads, $b mutates, $a reads${KEY:+ -- ENCRYPTED}"

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
  local final_a final_b da db
  final_a="$(run_impl "$a" read "$file")" || { bad "$a could not reopen after its own mutation"; return; }
  final_b="$(run_impl "$b" read "$file")" || { bad "$b could not reopen after ${a}'s mutation"; return; }
  da="$(field "$final_a" digest)"; db="$(field "$final_b" digest)"
  # An empty digest is not agreement. The first version of this comparison
  # tested two empty strings and reported `ok` while BOTH sides had failed to
  # open the file at all -- a control that cannot fail measures nothing, which
  # is this project's own recurring lesson and it reached its own test harness.
  if [[ -z "$da" || -z "$db" ]]; then
    bad "no digest after both mutated ($a='$da', $b='$db'): a reader failed to open the file"
  elif [[ "$da" == "$db" ]]; then
    ok "after mutations by both, they agree: digest $da"
  else
    bad "after both mutated: $a says $da, $b says $db"
  fi
}

say "building"
# `--features harness`: the interop tool is gated off by default so that it is
# not a binary of the published crate. See `cryptand/Cargo.toml`.
(cd "$rust" && cargo build --release -p cryptand -q --features harness --bin interop) || { echo "cargo build failed"; exit 1; }
[[ -x "$RUST" ]] || { echo "missing $RUST"; exit 1; }
ok "rust: built"
(cd "$java" && mvn -q -o -DskipTests test-compile) || { echo "maven build failed"; exit 1; }
# `JAVA_CP` is now two entries, so check them rather than the string.
for d in ${JAVA_CP//:/ }; do
  [[ -d "$d" ]] || { echo "missing $d"; exit 1; }
done
ok "java: built"

round_trip rust dart
round_trip dart rust
round_trip java rust
round_trip rust java
round_trip java dart
round_trip dart java

# The same gate over an encrypted file. `14-security.md` is the chapter with the
# most ways to be *individually* right and *mutually* incompatible -- the page
# AAD, the stored payload length, the per-record counter, the keyslot AAD and
# the superblock MAC are five independent chances for two implementations to
# each encrypt correctly and neither to read the other. A plaintext round trip
# exercises none of them.
KEY=0707070707070707070707070707070707070707070707070707070707070707
round_trip rust dart
round_trip dart rust
round_trip java rust
round_trip rust java
round_trip java dart
round_trip dart java

# And the other half of the property: the wrong key is refused, by both, with
# the one error `§3.3` allows -- "a failure across all slots is 'wrong key', and
# an implementation MUST NOT distinguish 'no such slot' from 'bad password'".
say "5. an encrypted file refuses the wrong key, in both implementations"
for impl in rust dart java; do
  out="$(KEY=0808080808080808080808080808080808080808080808080808080808080808 \
         run_impl "$impl" read "$work/rust-to-dart-enc.cryptand" 2>&1)" && \
    bad "$impl opened an encrypted file with the wrong key" || \
    ok "$impl refused the wrong key: $(head -1 <<<"$out")"
done
KEY=""

# F-067 / `01-container.md` §10: every writer locks the one byte at 2^62. A
# plain POSIX `fcntl` lock on that byte (what Java and Dart take) must keep
# every implementation from opening for writing.
if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != MSYS* ]] && command -v python3 >/dev/null; then
  say "6. a writer lock on byte 2^62 excludes every implementation"
  lf="$work/rust-to-dart.cryptand"
  python3 -c 'import fcntl,os,sys,time
fd=os.open(sys.argv[1],os.O_RDWR); fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,1,1<<62,0)
print("held",flush=True); time.sleep(120)' "$lf" > "$work/lock.out" &
  holder=$!
  for _ in $(seq 50); do grep -q held "$work/lock.out" 2>/dev/null && break; sleep 0.1; done
  for impl in rust dart java; do
    out="$(run_impl "$impl" mutate "$lf" "$impl" 2>&1)"
    if grep -qi "locked" <<<"$out"; then ok "$impl refused: $(grep -i locked <<<"$out" | head -1)"
    else bad "$impl was not refused as locked: $(tail -1 <<<"$out")"; fi
  done
  kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
fi

# F-072 / F-073, `14-security.md` §8.3: a file encrypted in place reads the
# same in every implementation, half-converted (plaintext and encrypted pages
# and value-log segments side by side; 14 §5.2 says a reader decides per
# object) and fully converted.
for conv in rust java; do
for mode in half full; do
  say "7. $conv encrypts in place ($mode); every implementation reads and verifies"
  ef="$work/encrypt-$conv-$mode.cryptand"
  run_impl $conv write "$ef" >/dev/null || { bad "$conv could not write"; continue; }
  want="$(field "$(run_impl $conv read "$ef")" digest)"
  KEY=0909090909090909090909090909090909090909090909090909090909090909
  extra=(); [[ $mode == half ]] && extra=(--half)
  run_impl $conv encrypt "$ef" ${extra[@]+"${extra[@]}"} >/dev/null || { bad "$conv could not encrypt"; KEY=""; continue; }
  for impl in rust java dart; do
    got="$(field "$(run_impl "$impl" read "$ef")" digest)"
    v="$(run_impl "$impl" verify "$ef" 2>&1 | tail -1)"
    if [[ "$got" == "$want" && "$v" == *" 0 findings"* ]]; then ok "$impl digest $got, $v"
    else bad "$impl: digest '$got' want '$want'; $v"; fi
  done
  KEY=""
done

for mode in half full; do
  say "8. $conv decrypts in place ($mode); every implementation reads and verifies"
  df="$work/decrypt-$conv-$mode.cryptand"
  KEY=0909090909090909090909090909090909090909090909090909090909090909
  run_impl $conv write "$df" >/dev/null || { bad "$conv could not write"; KEY=""; continue; }
  want="$(field "$(run_impl $conv read "$df")" digest)"
  extra=(); [[ $mode == half ]] && extra=(--half)
  run_impl $conv decrypt "$df" ${extra[@]+"${extra[@]}"} >/dev/null || { bad "$conv could not decrypt"; KEY=""; continue; }
  [[ $mode == full ]] && KEY=""   # decrypted: no key needed, and none accepted
  for impl in rust java dart; do
    got="$(field "$(run_impl "$impl" read "$df")" digest)"
    v="$(run_impl "$impl" verify "$df" 2>&1 | tail -1)"
    if [[ "$got" == "$want" && "$v" == *" 0 findings"* ]]; then ok "$impl digest $got, $v"
    else bad "$impl: digest '$got' want '$want'; $v"; fi
  done
  KEY=""
done
done

for rot in rust java; do
say "9. $rot rotates the master key (copy-and-swap); every implementation reads with the new key only"
rf="$work/rotate-$rot.cryptand"
KEY=0909090909090909090909090909090909090909090909090909090909090909
run_impl $rot write "$rf" >/dev/null || bad "$rot could not write"
want="$(field "$(run_impl $rot read "$rf")" digest)"
NEW=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
run_impl $rot rotate "$rf" "$NEW" >/dev/null || bad "$rot could not rotate"
for impl in rust java dart; do
  if run_impl "$impl" read "$rf" >/dev/null 2>&1; then bad "$impl still opens with the old key"; fi
done
KEY=$NEW
for impl in rust java dart; do
  got="$(field "$(run_impl "$impl" read "$rf")" digest)"
  v="$(run_impl "$impl" verify "$rf" 2>&1 | tail -1)"
  if [[ "$got" == "$want" && "$v" == *" 0 findings"* ]]; then ok "$impl digest $got, $v"
  else bad "$impl: digest '$got' want '$want'; $v"; fi
done
KEY=""
done

# F-079: index structures rooted in descriptors (R-tree, vector graph and
# region) survive conversion and rotation by either converter, and both Rust
# and Java verify them clean. Dart verify waits for M5 (its index storage).
for conv in rust java; do
  say "12. $conv encrypts, rotates and decrypts a java file with spatial and vector indexes"
  xf="$work/indexed-$conv.cryptand"
  KEY=""
  run_impl java write-indexed "$xf" >/dev/null || { bad "java could not write the indexed file"; continue; }
  K1=0909090909090909090909090909090909090909090909090909090909090909
  K2=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
  ok_idx() {  # ok_idx <stage>
    local q v1 v2
    q="$(run_impl java check-indexed "$xf" 2>&1 | tail -1)"
    v1="$(run_impl rust verify "$xf" 2>&1 | tail -1)"
    v2="$(run_impl java verify "$xf" 2>&1 | tail -1)"
    if [[ "$q" == "indexed: ok" && "$v1" == *" 0 findings"* && "$v2" == *" 0 findings"* ]]; then ok "$1: $q; rust $v1; java $v2"
    else bad "$1: $q; rust $v1; java $v2"; fi
  }
  KEY=$K1
  run_impl $conv encrypt "$xf" >/dev/null || bad "$conv could not encrypt"
  ok_idx "encrypted by $conv"
  run_impl $conv rotate "$xf" "$K2" >/dev/null || bad "$conv could not rotate"
  KEY=$K2; ok_idx "rotated by $conv"
  run_impl $conv decrypt "$xf" >/dev/null || bad "$conv could not decrypt"
  # decrypted: no key needed, and none accepted
  KEY=""; ok_idx "decrypted by $conv"
done

say "result"
if [[ $fail -eq 0 ]]; then
  printf '   \033[32mthe round-trip gate passes in both directions\033[0m\n'
else
  printf '   \033[31mthe round-trip gate FAILED\033[0m\n'
fi
exit $fail
