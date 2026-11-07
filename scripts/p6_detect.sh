#!/usr/bin/env bash
# P6: local SSH brute-force detection -> decisions (Mode B store).
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/env.sh

T=x86_64-unknown-linux-musl
BIN="target/$T/release"
DIR="$(mktemp -d /tmp/cslite-p6.XXXXXX)"
: >"$DIR/auth.log"

cat >"$DIR/cslite.yaml" <<EOF
mode: lapi
listen: 127.0.0.1:18084
api_key: "testkey"
log_level: debug
update_frequency: 10s

persistence:
  enabled: true
  path: $DIR/decisions.bin

capi:
  enabled: false

local_detection:
  enabled: true
  log_path: $DIR/auth.log
  ban_threshold: 3
  window: 60s
  ban_duration: 1h

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
    if curl -s -o /dev/null http://127.0.0.1:18084/health 2>/dev/null; then break; fi
    sleep 0.05
done

# 3 failures from .50 (threshold), 2 from .51 (below threshold)
for _ in 1 2 3; do
    echo "sshd[1]: Failed password for root from 203.0.113.50 port 22 ssh2" >>"$DIR/auth.log"
done
for _ in 1 2; do
    echo "sshd[1]: Failed password for root from 203.0.113.51 port 22 ssh2" >>"$DIR/auth.log"
done

out=""
for _ in $(seq 1 100); do
    out=$("$BIN/cslite" decisions list --config "$DIR/cslite.yaml" 2>/dev/null || true)
    if printf '%s' "$out" | grep -q 203.0.113.50; then break; fi
    sleep 0.1
done

echo "== decisions list =="
printf '%s\n' "$out" | grep -E 'ORIGIN|203\.0\.113\.5' || true
echo "== detection log =="
grep -E "detect:" "$DIR/srv.log" | tail -5 || true

if printf '%s' "$out" | grep -q 203.0.113.50 && ! printf '%s' "$out" | grep -q 203.0.113.51; then
    echo
    echo "P6 passed."
else
    echo "P6 FAIL"
    exit 1
fi
