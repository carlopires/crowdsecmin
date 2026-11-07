#!/usr/bin/env bash
# P3: admin API + CLI + persistence, exercised through the daemon (no root).
set -euo pipefail
cd "$(dirname "$0")/.."

T=x86_64-unknown-linux-musl
BIN="target/$T/release"
DIR="$(mktemp -d /tmp/cslite-p3.XXXXXX)"
CFG="$DIR/cslite.yaml"

[ -x "$BIN/cslited" ] || cargo build --release --target "$T" --quiet

cat >"$CFG" <<EOF
mode: lapi
listen: 127.0.0.1:18081
api_key: "testkey"
log_level: info

capi:
  enabled: false

persistence:
  enabled: true
  path: $DIR/decisions.bin

backend:
  mode: iptables
  blacklists_ipv4: cslitetest-blacklists
  blacklists_ipv6: cslitetest6-blacklists
  ipset_type: hash:net
  maxelem: 4096
  deny_action: DROP
  iptables_chains: [INPUT]
  add_rule_comments: false
  teardown_on_exit: false

limits:
  max_decisions: 1000
  max_bans_per_second: 50
EOF

SRV=""
start() {
    "$BIN/cslited" --config "$CFG" >>"$DIR/srv.log" 2>&1 &
    SRV=$!
    for _ in $(seq 1 100); do
        curl -s -o /dev/null http://127.0.0.1:18081/health && return 0
        sleep 0.05
    done
    echo "server did not start"; cat "$DIR/srv.log"; exit 1
}
stop() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null && wait "$SRV" 2>/dev/null || true; SRV=""; }
trap 'stop; rm -rf "$DIR"' EXIT

start
echo "== status =="; "$BIN/cslite" status --config "$CFG"
echo "== add (via daemon) =="; "$BIN/cslite" decisions add 203.0.113.7 --duration 1h --origin crowdsec --config "$CFG"
echo "== list =="; "$BIN/cslite" decisions list --config "$CFG"
echo "== test present =="; "$BIN/cslite" decisions test 203.0.113.7 --config "$CFG"
echo "== delta (startup=false) includes it =="
curl -s -H "X-Api-Key: testkey" "http://127.0.0.1:18081/v1/decisions/stream?startup=false" | grep -q 203.0.113.7 \
    && echo "ok: delta carried the add" || { echo "FAIL: delta missing add"; exit 1; }

echo "== delete =="; "$BIN/cslite" decisions delete 203.0.113.7 --config "$CFG"
if "$BIN/cslite" decisions test 203.0.113.7 --config "$CFG"; then echo "FAIL: still present"; exit 1; else echo "ok: absent"; fi

echo "== persistence across restart =="
"$BIN/cslite" decisions add 198.51.100.9 --duration 1h --config "$CFG"
stop; start
"$BIN/cslite" decisions list --config "$CFG" | grep -q 198.51.100.9 && echo "ok: survived restart" || { echo "FAIL: not persisted"; exit 1; }

echo "== bouncers =="
"$BIN/cslite" bouncers add testbouncer --config "$CFG"
"$BIN/cslite" bouncers list --config "$CFG"
echo "== bouncer key authorizes =="
KEY=$("$BIN/cslite" bouncers add k2 --config "$CFG" | sed -n "s/.*\"api_key\":\"\\([^\"]*\\)\".*/\\1/p")
curl -s -o /dev/null -w "  key status: %{http_code}\n" -H "X-Api-Key: $KEY" "http://127.0.0.1:18081/v1/decisions/stream?startup=true"

stop
echo
echo "P3 passed."
