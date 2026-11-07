#!/usr/bin/env bash
# T3/T4: ipset enforcement + kernel-side expiry.
#
# Runs inside a private network namespace (fresh, isolated IP set state) so it
# never touches the host's real sets. Requires passwordless sudo + unshare.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. scripts/env.sh

TARGET=x86_64-unknown-linux-musl
BIN="$(pwd)/target/$TARGET/release/cslite"
CFG="$(pwd)/deploy/cslite.test.yaml"
SD="$(mktemp -d /tmp/cslite-t3.XXXXXX)"

[ -x "$BIN" ] || cargo build --release --target "$TARGET" --quiet

cleanup() { rm -rf "$SD"; }
trap cleanup EXIT

sudo -n env BIN="$BIN" CFG="$CFG" SD="$SD" unshare --net bash -c '
set -euo pipefail
echo "== T3: add 203.0.113.7 (20s) =="
"$BIN" ipset add 203.0.113.7 --duration 20s --origin CAPI --config "$CFG" --state-dir "$SD"
ipset test cslitetest-blacklists-0 203.0.113.7
echo "-- set contents --"; ipset list cslitetest-blacklists-0 | tail -3

echo "== T3: reject bad input =="
if "$BIN" ipset add 1.2.3.4/33 --config "$CFG" --state-dir "$SD" 2>/dev/null; then
  echo "FAIL: /33 accepted"; exit 1
fi
echo "ok: bad prefix rejected"

echo "== T4: kernel expiry (wait 25s) =="
sleep 25
if ipset test cslitetest-blacklists-0 203.0.113.7 2>/dev/null; then
  echo "FAIL: entry still present after timeout"; exit 1
fi
echo "ok: expired by kernel, no daemon action"

echo "== CLI test reports absent (exit 1) =="
if "$BIN" ipset test 203.0.113.7 --origin CAPI --config "$CFG" --state-dir "$SD"; then
  echo "FAIL: cli said present"; exit 1
fi
echo "ok: cli reports absent"

echo "== IPv6 path =="
"$BIN" ipset add 2001:db8::1 --duration 60s --origin CAPI --config "$CFG" --state-dir "$SD"
ipset test cslitetest6-blacklists-0 2001:db8::1
echo "ok: v6 set cslitetest6-blacklists-0"

echo "== origin map persisted (no reshuffle) =="
cat "$SD/origins"

ipset destroy cslitetest-blacklists-0
ipset destroy cslitetest6-blacklists-0
echo
echo "T3/T4 passed."
'
