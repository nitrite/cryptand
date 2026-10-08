#!/bin/sh
# M2.3 disk full: mount a 200 MB image, run the Rust and Java ENOSPC tests on
# it, detach. macOS only (hdiutil). Usage: tools/enospc.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
img=$(mktemp -d)/enospc.dmg
hdiutil create -size 200m -fs HFS+ -volname cryptand-enospc "$img" >/dev/null
mnt=$(hdiutil attach -nobrowse "$img" | awk '/cryptand-enospc/ {print $NF}' | tail -1)
trap 'hdiutil detach -force "$mnt" >/dev/null; rm -f "$img"' EXIT
export CRYPTAND_ENOSPC_DIR="$mnt"
[ -n "${ENOSPC_JAVA_ONLY:-}" ] || (cd "$root/reference/rust" && cargo test -q --release -p cryptand --test enospc_test -- --nocapture)
[ -n "${ENOSPC_RUST_ONLY:-}" ] || (cd "$root/reference/java" && mvn -B -q test -Dtest=EnospcTest -Djacoco.skip=true)
echo "enospc: Rust and Java recovered on a 200 MB volume"
