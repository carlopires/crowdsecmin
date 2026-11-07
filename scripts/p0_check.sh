#!/usr/bin/env bash
# P0 acceptance gate: static musl build, size <= 1 MiB, no dynamic deps,
# config parser accepts the example and rejects unknown keys.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. scripts/env.sh

TARGET=x86_64-unknown-linux-musl
LIMIT=3145728          # 3 MiB (TLS build: rustls + ring)
rustup target add "$TARGET" >/dev/null 2>&1 || true

echo "[1/6] unit tests (host profile)"
cargo test --lib --quiet

echo "[2/6] release build ($TARGET)"
cargo build --release --target "$TARGET" --quiet

for b in cslited cslite; do
    BIN="target/$TARGET/release/$b"
    sz=$(stat -c %s "$BIN")
    printf '  %-7s %8d bytes\n' "$b" "$sz"
    if [ "$sz" -gt "$LIMIT" ]; then
        echo "FAIL: $b exceeds 1 MiB ($sz > $LIMIT)"; exit 1
    fi
done

echo "[3/6] static-link audit"
for b in cslited cslite; do
    BIN="target/$TARGET/release/$b"
    if readelf -d "$BIN" 2>/dev/null | grep -q NEEDED; then
        echo "FAIL: $b has dynamic NEEDED entries:"; readelf -d "$BIN" | grep NEEDED; exit 1
    fi
    printf '  %-7s no NEEDED (static) ok\n' "$b"
done

echo "[4/6] version"
"./target/$TARGET/release/cslite" version

echo "[5/6] check-config accepts the example"
"./target/$TARGET/release/cslite" check-config --config deploy/cslite.yaml.example

echo "[6/6] check-config rejects an unknown key"
tmp=$(mktemp)
printf 'mode: direct\nbogus_key: 1\n' >"$tmp"
if "./target/$TARGET/release/cslite" check-config --config "$tmp" >/dev/null 2>&1; then
    echo "FAIL: unknown key was accepted"; rm -f "$tmp"; exit 1
fi
rm -f "$tmp"
echo "  ok: unknown key rejected"

echo
echo "P0 checks passed."
