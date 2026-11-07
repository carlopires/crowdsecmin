#!/usr/bin/env bash
# T8 memory soak: run Mode B under decision churn, sample RSS, assert no drift.
#   SOAK_SECONDS=30 SOAK_INTERVAL=5 ./scripts/soak.sh        # quick
#   SOAK_SECONDS=86400 SOAK_INTERVAL=3600 ./scripts/soak.sh  # 24h
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/env.sh

T=x86_64-unknown-linux-musl
BIN="target/$T/release"
DIR="$(mktemp -d /tmp/cslite-soak.XXXXXX)"
SECS="${SOAK_SECONDS:-30}"
INTERVAL="${SOAK_INTERVAL:-5}"
THRESHOLD_KB="${SOAK_DRIFT_KB:-512}"

cat >"$DIR/cslite.yaml" <<EOF
mode: lapi
listen: 127.0.0.1:18085
api_key: "testkey"
log_level: info
update_frequency: 10s

persistence:
  enabled: true
  path: $DIR/decisions.bin

capi:
  enabled: false

backend:
  mode: iptables
  blacklists_ipv4: cslitetest-blacklists
  blacklists_ipv6: cslitetest6-blacklists
  ipset_type: hash:net
  maxelem: 131072
  deny_action: DROP
  iptables_chains: [INPUT]
  add_rule_comments: false
  teardown_on_exit: false

limits:
  max_decisions: 100000
  max_bans_per_second: 50
EOF

[ -x "$BIN/cslited" ] || { echo "build first"; exit 1; }
"$BIN/cslited" --config "$DIR/cslite.yaml" >"$DIR/srv.log" 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$DIR"' EXIT

for _ in $(seq 1 100); do
    if curl -s -o /dev/null http://127.0.0.1:18085/health 2>/dev/null; then break; fi
    sleep 0.05
done

echo "soak: ${SECS}s, interval ${INTERVAL}s, threshold ${THRESHOLD_KB} kB drift"
first=""
last=""
n=0
end=$((SECONDS + SECS))
while [ "$SECONDS" -lt "$end" ]; do
    ip="198.51.100.$((n % 250 + 1))"
    "$BIN/cslite" decisions add "$ip" --duration 30s --config "$DIR/cslite.yaml" >/dev/null 2>&1 || true
    "$BIN/cslite" decisions delete "$ip" --config "$DIR/cslite.yaml" >/dev/null 2>&1 || true
    n=$((n + 1))
    sleep "$INTERVAL"
    if ! kill -0 "$SRV" 2>/dev/null; then
        echo "SOAK FAIL: daemon exited"; cat "$DIR/srv.log"; exit 1
    fi
    rss=$(awk '/^RssAnon/{print $2}' "/proc/$SRV/status")
    file=$(awk '/^RssFile/{print $2}' "/proc/$SRV/status")
    [ -z "$first" ] && first=$rss
    last=$rss
    echo "  t=$((SECONDS)) RssAnon=${rss} kB RssFile=${file} kB cycles=${n}"
done

drift=$((last - first))
echo "RssAnon drift: ${drift} kB (first=${first}, last=${last})"
if [ "$drift" -gt "$THRESHOLD_KB" ]; then
    echo "SOAK FAIL: drift ${drift} kB > ${THRESHOLD_KB} kB"
    exit 1
fi
echo "SOAK passed."
